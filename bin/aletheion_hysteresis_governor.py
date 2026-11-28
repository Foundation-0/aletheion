#!/usr/bin/env python3
"""Aletheion Pure-Z/Q Hysteresis Thermal Governor (`bin/aletheion_hysteresis_governor.py`).

Offline pure-Z/Q thermal-ladder simulator, transition step function, and certificate
verifier for UX582HS temperature traces combining three coordinate-free damping operators:
  1. Stepped-impedance 2-chamber spike filter (Petra conduit impedance law),
  2. Asymmetric deadband thermal gear ladder (Al-Jazari float-valve hysteresis),
  3. Bilinear Coulomb friction-hysteresis loop dissipation identity (Dougong bracket law).

Policy invariant: strictly models temperature stability (deg C) and state-switch chatter
elimination ONLY — zero uncontrolled laptop energy/wattage claims, zero IEEE-754 float
literals in AST, zero bare asserts.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple
import unicodedata

SCHEMA_GOV = "aletheion.hysteresis_thermal_governor.v1"
TELEMETRY_SCOPE_POLICY = "TEMPERATURE_AND_CHATTER_ONLY"
MAX_JSON_DEPTH = 32
MAX_INT_ABS = 10**18
MAX_POLICY_TEXT_LEN = 4096
MAX_INPUT_BYTES = 16 * 1024 * 1024

# UX582HS sustained thermal gear ladder (exact rational degrees C, 5 C deadband):
#   Gear 0 (NOMINAL)     -> escalates to 1 at >= 70 C; returns from 1 at <= 65 C
#   Gear 1 (WARM_STEP)   -> escalates to 2 at >= 78 C (GPU knee); returns from 2 at <= 73 C
#   Gear 2 (HIGH_GUARD)  -> escalates to 3 at >= 85 C (CPU knee); returns from 3 at <= 80 C
#   Gear 3 (CLAMP_GUARD) -> ceiling clamp / display-dim target gear
DEFAULT_UP_KNEES = (Fraction(70, 1), Fraction(78, 1), Fraction(85, 1))
DEFAULT_DN_KNEES = (Fraction(65, 1), Fraction(73, 1), Fraction(80, 1))

_ALLOWED_POWER_BANDS: FrozenSet[str] = frozenset({"ac", "battery", "unknown"})
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEY_TOKENS: FrozenSet[str] = frozenset(
    {
        "w",
        "j",
        "watt",
        "watts",
        "watthour",
        "watthours",
        "whr",
        "whrs",
        "pw",
        "nw",
        "uw",
        "mw",
        "kw",
        "gw",
        "tw",
        "wh",
        "kwh",
        "mwh",
        "gwh",
        "twh",
        "pj",
        "nj",
        "uj",
        "mj",
        "kj",
        "gj",
        "tj",
        "joule",
        "joules",
        "picowatt",
        "picowatts",
        "nanowatt",
        "nanowatts",
        "microwatt",
        "microwatts",
        "milliwatt",
        "milliwatts",
        "kilowatt",
        "kilowatts",
        "megawatt",
        "megawatts",
        "gigawatt",
        "gigawatts",
        "terawatt",
        "terawatts",
        "kilojoule",
        "kilojoules",
        "millijoule",
        "millijoules",
        "microjoule",
        "microjoules",
        "megajoule",
        "megajoules",
        "tdp",
        "pwr",
        "power",
        "energy",
        "wattage",
        "rapl",
    }
)
_FORBIDDEN_GLUED_TOKEN_RE = re.compile(
    r"(?:watt|joule|energy|power|nvmldevicegetpower|nvmldevicegettotalenergy)"
    r"|^(?:mj|j|uj|w|wh|kwh|mwh)pertok(?:en)?s?$"
    r"|^tok(?:en)?s?per(?:mj|j|uj|w|wh|kwh|mwh)$"
    r"|^(?:avg|max|min|pkg|gpu|cpu|nvml|total)(?:power|energy|watt|tdp|pwr|mw|uj|mj|wh|kwh|mwh)$"
    r"|^(?:intel)?rapl$"
)
_PFX = r"(?:p|n|u|\u03bc|m|k|g|t|pico|nano|micro|milli|kilo|mega|giga|tera)"
_UNIT = r"(?:wattage|watt[^a-z0-9]{0,2}hours?|watthours?|watts?|joules?|whrs?|wh|w|j|tdp)"
_FULL_UNIT = r"(?:wattage|watt[^a-z0-9]{0,2}hours?|watthours?|watts?|joules?|whrs?|wh|tdp)"
_SEP = r"[^a-z0-9]{0,4}"
_NUM = r"(?<!\d)\d{1,18}(?:[.,]\d{1,18}){0,4}(?:e[+-]?\d{1,4})?"
_MOD = r"(?:[a-z]{1,24}[\s_]{1,4}){0,2}"
_WORD_NUM = (
    r"(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|"
    r"fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|"
    r"sixty|seventy|eighty|ninety|hundred|thousand)"
    r"(?:[-\s]{1,2}(?:one|two|three|four|five|six|seven|eight|nine|hundred|thousand)){0,2}"
)
_FORBIDDEN_VALUE_RE = re.compile(
    "(?:"
    rf"{_NUM}{_SEP}(?:{_PFX}{_SEP})?{_UNIT}(?![a-z0-9])(?!/o(?![a-z0-9])|/\s+(?!tok(?:en)?s?(?![a-z0-9])|s(?:ec(?:ond)?s?)?(?![a-z0-9])))"
    rf"|(?<![a-z0-9])(?:{_PFX}{_SEP})?{_UNIT}(?:\s{{0,4}}[:_]\s{{0,4}}|=){_NUM}"
    rf"|(?<![a-z0-9])(?:(?:{_PFX}{_SEP})?{_FULL_UNIT}|{_PFX}{_SEP}[wj])\s{{0,4}}=\s{{0,4}}{_NUM}"
    rf"|(?<![a-z0-9])(?:energy|power)\s{{0,4}}[:=_]\s{{0,4}}{_NUM}"
    rf"|(?<![a-z0-9]){_WORD_NUM}\s{{1,4}}(?:{_PFX}[\s-]{{0,2}})?(?:watts?|joules?|watt[-\s]?hours?|watthours?)(?![a-z0-9])"
    rf"|(?<![a-z0-9])tdp[^a-z0-9]{{0,4}}{_NUM}"
    rf"|^[^a-z0-9]{{0,4}}(?:{_PFX}{_SEP})?{_UNIT}[^a-z0-9]{{0,4}}$"
    rf"|(?<![a-z0-9])(?:(?:{_PFX}[\s_]{{0,2}})?(?:joules?|watts?|whrs?|wh|j)|{_PFX}[\s_]{{0,2}}w|energy|power)(?:[\s_]{{1,4}}per[\s_]{{1,4}}|\s{{0,4}}/\s{{0,4}}){_MOD}tok(?:en)?s?(?![a-z0-9])"
    rf"|(?<![a-z0-9])w(?:[\s_]{{1,4}}per[\s_]{{1,4}}|/(?!\s)){_MOD}tok(?:en)?s?(?![a-z0-9])"
    rf"|(?<![a-z0-9])tok(?:en)?s?(?:[\s_]{{1,4}}per[\s_]{{1,4}}|\s{{0,4}}/\s{{0,4}}){_MOD}(?:(?:{_PFX}[\s_]{{0,2}})?(?:joules?|watts?|whrs?|wh|j|w)|energy|power)(?![a-z0-9])"
    r"|(?<![a-z0-9])(?:(?:peak|mean|avg|average|max|min|total|gpu|cpu|laptop|system|board|pkg|package|wall|socket|measured|reported|low|lower|high|reduced)\s{1,4}(?:[a-z]{1,24}\s{1,4})?wattage|wattage\s{1,4}(?:draw|use|usage|consumption|reduction|savings?|limit|cap|budget|reading|measurement|telemetry))(?![a-z0-9])"
    r"|(?<![a-z0-9])(?:intel[-_ ]?)?rapl(?![a-z0-9])"
    r"|(?<![a-z0-9])nvml[-_ ]{0,4}(?:device[-_ ]{0,4}get[-_ ]{0,4})?(?:total[-_ ]{0,4})?(?:power|energy|watt|(?:mw|uj)(?![a-z0-9]))"
    r"|(?<![a-z0-9])nvidia[-_ ]?smi(?![a-z0-9])(?:(?:\s{0,8}$)|[^;\n]{0,256}(?<![a-z0-9])(?:power|watt|energy|draw|tdp)(?![a-z0-9]))"
    r"|(?<![a-z0-9])(?:less|lower|reduced|fewer)\s{1,4}(?:in\s{1,4})?(?:energy|power)(?![a-z0-9])"
    r"|(?<![a-z0-9])(?:energy|power)\s{1,4}(?:use|usage|reduction|savings?|dropped|consumption|draw)(?![a-z0-9])"
    ")"
)
_FORBIDDEN_SYS_PREFIXES: Tuple[str, ...] = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var",
)


class ThermalGovError(ValueError):
    """Fail-closed error for Aletheion hysteresis thermal governor."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"[{code}] {detail}")


def require_ok(cond: bool, code: str, detail: str) -> None:
    if not cond:
        raise ThermalGovError(code, detail)


def check_frac(val: Any, name: str) -> Fraction:
    if type(val) is Fraction:
        require_ok(abs(val.numerator) <= MAX_INT_ABS and val.denominator <= MAX_INT_ABS, "FRAC_RANGE", name)
        return val
    if type(val) is int:
        require_ok(abs(val) <= MAX_INT_ABS, "INT_RANGE", name)
        return Fraction(val, 1)
    raise ThermalGovError("BAD_FRAC", f"{name} must be Fraction or int")


def check_pos_int(val: Any, name: str) -> int:
    require_ok(type(val) is int and 0 < val <= MAX_INT_ABS, "BAD_POS_INT", f"{name} must be positive int")
    return val


def frac_str(x: Fraction) -> str:
    return f"{x.numerator}/{x.denominator}"


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def is_hex64(val: Any) -> bool:
    return type(val) is str and _HEX64_RE.fullmatch(val) is not None


def _fold_and_reject_non_ascii_letters(text: str) -> str:
    """NFKC -> NFKD -> drop Cf/Mn -> reject non-ASCII letters (except micro sign)."""
    require_ok(len(text) <= MAX_POLICY_TEXT_LEN, "POLICY_TEXT_TOO_LONG", "Policy-scanned text exceeds length cap")
    nfkd = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text))
    stripped = "".join(ch for ch in nfkd if unicodedata.category(ch) not in ("Cf", "Mn"))
    require_ok(
        not any(ord(ch) > 127 and ch.isalpha() and ch not in ("\u03bc", "\u00b5") for ch in stripped),
        "NON_ASCII_POLICY_TEXT",
        "Non-ASCII letters forbidden in policy-scanned governor text",
    )
    return stripped


def _normalize_policy_text(text: str) -> str:
    return _fold_and_reject_non_ascii_letters(text).casefold()


def _check_policy_key_value(key: str, val: Any) -> None:
    clean_k = _fold_and_reject_non_ascii_letters(key)
    if clean_k.casefold() == "power_band":
        require_ok(type(val) is str and _normalize_policy_text(val).strip() in _ALLOWED_POWER_BANDS, "BAD_POWER_BAND", "power_band must be ac|battery|unknown")
        return
    spaced_k = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", clean_k).replace("_", " ").casefold()
    tokens = [tok for tok in re.split(r"[^a-z0-9\u03bc]+", spaced_k) if tok]
    if (
        any(_FORBIDDEN_GLUED_TOKEN_RE.search(tok) is not None for tok in tokens)
        or "".join(tokens) in _FORBIDDEN_KEY_TOKENS
        or _FORBIDDEN_VALUE_RE.search(spaced_k) is not None
        or any(tok in _FORBIDDEN_KEY_TOKENS for tok in tokens)
    ):
        raise ThermalGovError("FORBIDDEN_ENERGY_KEY", f"Energy/power key forbidden: {key}")


def _check_policy_string_value(val: str) -> None:
    norm_s = _normalize_policy_text(val)
    require_ok(_FORBIDDEN_VALUE_RE.search(norm_s) is None, "FORBIDDEN_ENERGY_VAL", f"Energy/power claim forbidden: {val}")


def validate_json_tree_no_floats(root: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Iterative depth-capped validator rejecting floats, non-JSON containers, and energy/power claims."""
    require_ok(type(max_depth) is int and 0 <= max_depth <= MAX_INT_ABS, "BAD_MAX_DEPTH", "max_depth must be non-negative int")
    stack: List[Tuple[Any, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        require_ok(depth <= max_depth, "JSON_DEPTH", "JSON nesting exceeds cap")
        t = type(node)
        if t is float:
            raise ThermalGovError("FLOAT_FORBIDDEN", "Float forbidden in pure-Q governor certificate")
        if t is dict:
            for k, v in node.items():
                require_ok(type(k) is str, "BAD_KEY", "Dict key must be str")
                _check_policy_key_value(k, v)
                stack.append((v, depth + 1))
        elif t is list:
            for item in node:
                stack.append((item, depth + 1))
        elif t is str:
            _check_policy_string_value(node)
        elif t in (int, bool) or node is None:
            continue
        else:
            raise ThermalGovError("BAD_JSON_TYPE", f"Unsupported type {t.__name__}")


def petra_stepped_filter_q(
    trace_c: Sequence[Any],
    k1: int = 2,
    k2: int = 2,
) -> List[Fraction]:
    """2-stage pure-Q chamber-impedance filter: y_{t+1} = y_t + (T_t - y_t)/k1, z_{t+1} = z_t + (y_{t+1} - z_t)/k2."""
    require_ok(type(trace_c) in (list, tuple) and len(trace_c) >= 1, "EMPTY_TRACE", "Trace must be non-empty list/tuple")
    c1 = check_pos_int(k1, "k1")
    c2 = check_pos_int(k2, "k2")
    require_ok(c1 >= 2 and c2 >= 2, "BAD_CHAMBER_K", "Stepped chamber impedances k1, k2 must be >= 2")
    vals = [check_frac(x, f"trace[{i}]") for i, x in enumerate(trace_c)]
    y = vals[0]
    z = vals[0]
    out: List[Fraction] = [z]
    inv1 = Fraction(1, c1)
    inv2 = Fraction(1, c2)
    for t_val in vals[1:]:
        y = y + inv1 * (t_val - y)
        z = z + inv2 * (y - z)
        out.append(z)
    return out


def validate_knee_ladder(up_knees: Sequence[Fraction], dn_knees: Sequence[Fraction]) -> Tuple[Tuple[Fraction, ...], Tuple[Fraction, ...]]:
    require_ok(type(up_knees) in (list, tuple) and type(dn_knees) in (list, tuple), "BAD_KNEES_TYPE", "up/dn knees must be list/tuple")
    require_ok(len(up_knees) >= 1 and len(up_knees) == len(dn_knees), "BAD_KNEES_LEN", "up/dn knees must match len >= 1")
    ups = tuple(check_frac(x, "up_knee") for x in up_knees)
    dns = tuple(check_frac(x, "dn_knee") for x in dn_knees)
    for i in range(len(ups)):
        require_ok(dns[i] < ups[i], "NONPOS_DEADBAND", "Each deadband must satisfy dn_knee < up_knee")
        if i > 0:
            require_ok(ups[i - 1] < ups[i] and dns[i - 1] < dns[i], "NON_MONO_KNEES", "Knees must be strictly increasing")
    return ups, dns


def step_hysteresis_gear(
    current_gear: int,
    temp_c: Fraction,
    up_knees: Sequence[Fraction],
    dn_knees: Sequence[Fraction],
) -> int:
    """Single-step Al-Jazari float-valve deadband transition (zero floats, exact Fraction comparison)."""
    ups, dns = validate_knee_ladder(up_knees, dn_knees)
    n_gears = len(ups)
    require_ok(type(current_gear) is int and 0 <= current_gear <= n_gears, "BAD_GEAR", "Gear out of range")
    tv = check_frac(temp_c, "temp_c")
    gear = current_gear
    while gear < n_gears and tv >= ups[gear]:
        gear += 1
    while gear > 0 and tv <= dns[gear - 1]:
        gear -= 1
    return gear


def simulate_hysteresis_vs_bangbang(
    trace_c: Sequence[Any],
    *,
    up_knees: Sequence[Fraction] = DEFAULT_UP_KNEES,
    dn_knees: Sequence[Fraction] = DEFAULT_DN_KNEES,
    k1: int = 2,
    k2: int = 2,
) -> Dict[str, Any]:
    """Compare filtered Al-Jazari/Petra/Dougong hysteresis governor vs zero-hysteresis bang-bang comparator."""
    ups, dns = validate_knee_ladder(up_knees, dn_knees)
    require_ok(type(trace_c) in (list, tuple), "EMPTY_TRACE", "Trace must be non-empty list/tuple")
    raw = [check_frac(x, f"trace[{i}]") for i, x in enumerate(trace_c)]
    filtered = petra_stepped_filter_q(raw, k1=k1, k2=k2)

    bb_gears: List[int] = []
    bb_switches = 0
    for tv in raw:
        g = sum(1 for u in ups if tv >= u)
        if bb_gears and g != bb_gears[-1]:
            bb_switches += 1
        bb_gears.append(g)

    hyst_gears: List[int] = []
    hyst_switches = 0
    g_cur = sum(1 for u in ups if filtered[0] >= u)
    hyst_gears.append(g_cur)
    for fv in filtered[1:]:
        g_nxt = step_hysteresis_gear(g_cur, fv, ups, dns)
        if g_nxt != g_cur:
            hyst_switches += 1
        g_cur = g_nxt
        hyst_gears.append(g_cur)

    return {
        "n_ticks": len(raw),
        "bangbang_switches": bb_switches,
        "hysteresis_switches": hyst_switches,
        "bangbang_final_gear": bb_gears[-1],
        "hysteresis_final_gear": hyst_gears[-1],
        "hysteresis_max_gear": max(hyst_gears),
        "hysteresis_min_gear": min(hyst_gears),
        "filtered_peak_c": frac_str(max(filtered)),
    }


def dougong_deadband_loop_q(
    stiffness_k: Any,
    slip_half_band_uy: Any,
    peak_excursion_um: Any,
    hardening_alpha: Any = Fraction(0, 1),
) -> Dict[str, Any]:
    """Exact pure-Q Dougong Coulomb friction-hysteresis loop area identity."""
    kf = check_frac(stiffness_k, "stiffness_k")
    uy = check_frac(slip_half_band_uy, "slip_half_band_uy")
    um = check_frac(peak_excursion_um, "peak_excursion_um")
    af = check_frac(hardening_alpha, "hardening_alpha")
    require_ok(kf > 0 and uy > 0, "NONPOS_PARAM", "stiffness_k and slip_half_band_uy must be > 0")
    require_ok(um > uy, "NO_SLIP", "peak_excursion_um must exceed slip_half_band_uy")
    require_ok(Fraction(0, 1) <= af <= Fraction(1, 1), "BAD_ALPHA", "hardening_alpha must lie in [0, 1]")

    f_y = kf * uy
    f_m = f_y + af * kf * (um - uy)
    verts = (
        (um, f_m),
        (um - Fraction(2, 1) * uy, f_m - Fraction(2, 1) * f_y),
        (-um, -f_m),
        (-um + Fraction(2, 1) * uy, -f_m + Fraction(2, 1) * f_y),
    )
    twice_area = Fraction(0, 1)
    for i in range(4):
        x1, y1 = verts[i]
        x2, y2 = verts[(i + 1) % 4]
        twice_area += x1 * y2 - x2 * y1
    e_shoelace = abs(twice_area) / Fraction(2, 1)
    e_formula = Fraction(4, 1) * f_y * (um - uy) * (Fraction(1, 1) - af)
    return {
        "e_diss_shoelace": frac_str(e_shoelace),
        "e_diss_formula": frac_str(e_formula),
        "area_residual": frac_str(e_shoelace - e_formula),
        "exact_match": e_shoelace == e_formula,
    }


def certify_thermal_governor() -> Dict[str, Any]:
    """Certify zero limit-cycle chatter, stepped ramp + glitch immunity, and Dougong loop identity."""
    chatter_trace = [78 if i == 0 else (76 if i % 2 == 1 else 79) for i in range(40)]
    g1 = simulate_hysteresis_vs_bangbang(chatter_trace)
    g1_pass = all((g1["bangbang_switches"] == 39, g1["hysteresis_switches"] == 0, g1["hysteresis_final_gear"] == 2))

    glitch_trace = [66, 66, 72, 66, 66, 66]
    g2_glitch = simulate_hysteresis_vs_bangbang(glitch_trace)
    ramp_trace = [55, 62, 72, 75, 76, 80, 82, 84, 88, 90, 90, 84, 78, 74, 70, 68, 64, 62, 60, 58]
    g2_ramp = simulate_hysteresis_vs_bangbang(ramp_trace)
    g2_pass = all(
        (
            g2_glitch["bangbang_switches"] == 2,
            g2_glitch["hysteresis_switches"] == 0,
            g2_glitch["filtered_peak_c"] == "135/2",
            g2_ramp["hysteresis_max_gear"] == 3,
            g2_ramp["hysteresis_final_gear"] == 0,
        )
    )

    g3_coulomb = dougong_deadband_loop_q(Fraction(4, 1), Fraction(5, 2), Fraction(5, 1), Fraction(0, 1))
    g3_elastic = dougong_deadband_loop_q(Fraction(4, 1), Fraction(5, 2), Fraction(5, 1), Fraction(1, 1))
    g3_pass = all(
        (
            g3_coulomb["exact_match"],
            g3_coulomb["area_residual"] == "0/1",
            g3_coulomb["e_diss_shoelace"] == "100/1",
            g3_elastic["exact_match"],
            g3_elastic["e_diss_shoelace"] == "0/1",
        )
    )

    all_passed = all((g1_pass, g2_pass, g3_pass))
    payload: Dict[str, Any] = {
        "schema": SCHEMA_GOV,
        "zero_floats": True,
        "telemetry_scope_policy": TELEMETRY_SCOPE_POLICY,
        "g1_zero_chatter": {"metrics": g1, "passed": g1_pass},
        "g2_glitch_and_ramp": {"glitch": g2_glitch, "ramp": g2_ramp, "passed": g2_pass},
        "g3_dougong_loop": {"coulomb": g3_coulomb, "elastic": g3_elastic, "passed": g3_pass},
        "all_passed": all_passed,
    }
    p_sha = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    cert = dict(payload)
    cert["payload_sha256"] = p_sha
    cert["certificate_sha256"] = hashlib.sha256(_canonical_json_bytes(cert)).hexdigest()
    validate_governor_certificate(cert)
    return cert


def validate_governor_certificate(cert: Any) -> None:
    """Fail-closed semantic & cryptographic validation enforced in BOTH build and check."""
    validate_json_tree_no_floats(cert)
    require_ok(type(cert) is dict, "BAD_CERT_ROOT", "Certificate root must be dict")
    req = (
        "schema",
        "zero_floats",
        "telemetry_scope_policy",
        "g1_zero_chatter",
        "g2_glitch_and_ramp",
        "g3_dougong_loop",
        "all_passed",
        "payload_sha256",
        "certificate_sha256",
    )
    for k in req:
        require_ok(k in cert, "MISSING_KEY", f"Missing required key {k}")
    require_ok(set(cert.keys()) == set(req), "EXTRA_KEY", "Unexpected top-level certificate keys")
    require_ok(cert["schema"] == SCHEMA_GOV, "BAD_SCHEMA", "Schema mismatch")
    require_ok(cert["zero_floats"] is True, "BAD_ZERO_FLOATS", "zero_floats must be True")
    require_ok(cert["telemetry_scope_policy"] == TELEMETRY_SCOPE_POLICY, "BAD_SCOPE_POLICY", "Invalid telemetry scope policy")

    for sec_key in ("g1_zero_chatter", "g2_glitch_and_ramp", "g3_dougong_loop"):
        sec = cert[sec_key]
        require_ok(type(sec) is dict, "BAD_SECTION", f"{sec_key} must be dict")
        pf = sec.get("passed")
        require_ok(type(pf) is bool, "BAD_PASS_FLAG", f"{sec_key}.passed must be bool")
        require_ok(pf, "GATE_FAILED", f"{sec_key} failed")
    require_ok(cert["all_passed"] is True, "ALL_PASSED_FALSE", "all_passed must be True")

    payload = {k: cert[k] for k in cert if k not in ("payload_sha256", "certificate_sha256")}
    exp_p = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    got_p = cert["payload_sha256"]
    require_ok(is_hex64(got_p) and hmac.compare_digest(got_p, exp_p), "PAYLOAD_SHA_MISMATCH", "payload_sha256 mismatch")
    body = dict(payload)
    body["payload_sha256"] = exp_p
    exp_c = hashlib.sha256(_canonical_json_bytes(body)).hexdigest()
    got_c = cert["certificate_sha256"]
    require_ok(is_hex64(got_c) and hmac.compare_digest(got_c, exp_c), "CERT_SHA_MISMATCH", "certificate_sha256 mismatch")


def _is_forbidden_system_path(path_str: str) -> bool:
    norm = re.sub(r"^/+", "/", path_str)
    if norm == "/":
        return True
    if norm.startswith("/dev/shm/"):
        return False
    return any(norm == pfx or norm.startswith(pfx + "/") for pfx in _FORBIDDEN_SYS_PREFIXES)


def _check_safe_path(path: Path, label: str) -> Path:
    require_ok(isinstance(path, Path), "BAD_CERT_PATH", f"{label} must be Path")
    raw = str(path)
    require_ok(
        "\x00" not in raw and ".." not in path.parts and not raw.startswith("//"),
        "UNSAFE_PATH",
        f"{label} contains NUL, '..', or leading '//'",
    )
    try:
        raw.encode("utf-8")
        abs_path = Path(os.path.abspath(raw))
        real_parent = Path(os.path.realpath(str(abs_path.parent)))
    except (OSError, UnicodeEncodeError) as exc:
        raise ThermalGovError("UNSAFE_PATH", f"{label} path resolution failed: {exc}") from exc
    resolved = real_parent / abs_path.name
    require_ok(not _is_forbidden_system_path(resolved.as_posix()), "UNSAFE_PATH", f"{label} targets forbidden system path")
    require_ok(not resolved.is_symlink(), "UNSAFE_PATH", f"{label} symlink target forbidden")
    return resolved


def _read_text_safe(path: Path, label: str) -> str:
    safe = _check_safe_path(path, label)
    parent_fd = -1
    fd = -1
    try:
        parent_fd = os.open(str(safe.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fd = os.open(safe.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        st = os.fstat(fd)
        require_ok(stat.S_ISREG(st.st_mode), "UNSAFE_PATH", f"{label} must be a regular file")
        require_ok(st.st_size <= MAX_INPUT_BYTES, "READ_OR_JSON_ERR", f"{label} exceeds max size cap")
        os.set_blocking(fd, True)
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read(MAX_INPUT_BYTES).decode("utf-8")
    except ThermalGovError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise ThermalGovError("READ_OR_JSON_ERR", f"Failed to read governor cert: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _write_text_safe(path: Path, text: str) -> None:
    safe = _check_safe_path(path, "write")
    require_ok(safe.parent.is_dir(), "BAD_WRITE_PARENT", "Write target parent directory must exist")
    parent_fd = -1
    fd = -1
    tmp_name = f".{safe.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    created_tmp = False
    try:
        parent_fd = os.open(str(safe.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            existing = os.stat(safe.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            require_ok(stat.S_ISREG(existing.st_mode), "UNSAFE_PATH", "Write target must be a regular file")
            require_ok(existing.st_nlink == 1, "UNSAFE_PATH", "Write target hardlink forbidden")
        fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent_fd)
        created_tmp = True
        raw = text.encode("utf-8")
        view = memoryview(raw)
        pos = 0
        while pos < len(view):
            n = os.write(fd, view[pos:])
            require_ok(n > 0, "WRITE_ERR", "Short write to governor cert temp file")
            pos += n
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp_name, safe.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        created_tmp = False
    except ThermalGovError:
        raise
    except OSError as exc:
        raise ThermalGovError("WRITE_ERR", f"Failed to write governor cert: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if created_tmp:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd >= 0:
            os.close(parent_fd)


MAX_JSON_INT_DIGITS = 64
MAX_STRICT_JSON_DEPTH = 64


def _check_json_depth(obj: Any, max_depth: int, label: str) -> None:
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        cur, depth = stack.pop()
        require_ok(depth <= max_depth, "JSON_DEPTH", f"{label}: JSON nesting depth exceeds {max_depth}")
        if type(cur) is dict:
            for v in cur.values():
                stack.append((v, depth + 1))
        elif type(cur) is list:
            for v in cur:
                stack.append((v, depth + 1))


def _loads_strict_json(raw_text: str, label: str) -> Any:
    def _reject_const(tok: str) -> Any:
        raise ThermalGovError("NON_FINITE_JSON", f"{label}: non-finite JSON constant {tok!r} forbidden")

    def _reject_float(tok: str) -> Any:
        raise ThermalGovError("FLOAT_FORBIDDEN", f"{label}: float literal {tok!r} forbidden")

    def _parse_bounded_int(tok: str) -> int:
        digits = tok[1:] if tok.startswith("-") else tok
        require_ok(len(digits) <= MAX_JSON_INT_DIGITS, "INT_TOO_LONG", f"{label}: integer exceeds {MAX_JSON_INT_DIGITS} digits")
        return int(tok)

    def _reject_dup_keys(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in pairs:
            require_ok(k not in out, "DUPLICATE_JSON_KEY", f"{label}: duplicate JSON key {k!r}")
            out[k] = v
        return out

    try:
        parsed = json.loads(
            raw_text,
            parse_constant=_reject_const,
            parse_float=_reject_float,
            parse_int=_parse_bounded_int,
            object_pairs_hook=_reject_dup_keys,
        )
    except ThermalGovError:
        raise
    except RecursionError as exc:
        raise ThermalGovError("JSON_DEPTH", f"{label}: JSON nesting depth exceeds recursion limit") from exc
    except ValueError as exc:
        raise ThermalGovError("READ_OR_JSON_ERR", f"Failed to parse {label}: {exc}") from exc
    _check_json_depth(parsed, MAX_STRICT_JSON_DEPTH, label)
    return parsed


def check_certificate_file(path: Path) -> Dict[str, Any]:
    raw_text = _read_text_safe(path, "check")
    data = _loads_strict_json(raw_text, "governor cert")
    validate_governor_certificate(data)
    expected = certify_thermal_governor()
    require_ok(
        hmac.compare_digest(data["certificate_sha256"], expected["certificate_sha256"]),
        "LIVE_RECOMPUTE_MISMATCH",
        "Governor cert does not match live pure-Q recomputation",
    )
    return data


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Aletheion Pure-Q Al-Jazari/Petra/Dougong Thermal Governor")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--standalone", action="store_true", help="Print canonical JSON certificate (default)")
    group.add_argument("--write", type=Path, help="Write canonical JSON certificate to path")
    group.add_argument("--check", type=Path, help="Fail-closed verify certificate against live recomputation")
    args = parser.parse_args(argv)
    try:
        if args.check is not None:
            cert = check_certificate_file(args.check)
            print(json.dumps({"status": "PASS", "certificate_sha256": cert["certificate_sha256"]}, sort_keys=True))
            return 0
        cert = certify_thermal_governor()
        out_text = json.dumps(cert, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
        if args.write is not None:
            _write_text_safe(args.write, out_text)
            print(json.dumps({"status": "WRITTEN", "certificate_sha256": cert["certificate_sha256"]}, sort_keys=True))
            return 0
        sys.stdout.write(out_text)
        return 0
    except ThermalGovError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
