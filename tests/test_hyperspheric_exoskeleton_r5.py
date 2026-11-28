#!/usr/bin/env python3
"""Assertion-free R5 verification & adversarial tamper-refusal suite for Aletheion Hyperspheric Exoskeleton:
  - bin/hyperspheric-hud.py
  - bin/aletheion_hysteresis_governor.py
  - bin/aletheion_exoskeleton_plugins.py

Pure Python stdlib, zero bare asserts, zero external filesystem dependencies, 3-mode -I parity,
and adversarial boundary/policy/tamper test coverage designed for external mutation-kill verification.
"""

from __future__ import annotations

import ast
import copy
from fractions import Fraction
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = REPO_ROOT / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


def _load_hyphen_module(mod_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(mod_name, file_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module {file_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


hud = _load_hyphen_module("hyperspheric_hud", BIN_DIR / "hyperspheric-hud.py")
import aletheion_exoskeleton_plugins as plug
import aletheion_hysteresis_governor as gov


def _resign_hud_snap(snap: dict) -> dict:
    out = copy.deepcopy(snap)
    payload = {k: out[k] for k in out if k not in ("captured_unix_s", "snapshot_sha256")}
    out["snapshot_sha256"] = hashlib.sha256(hud.canonical_json_bytes(payload)).hexdigest()
    return out


# Full in-repo 89-case adversarial energy-claim corpus: (payload_dict, expected_error_code)
ADVERSARIAL_ENERGY_CASES: tuple[tuple[dict, str], ...] = (
    # --- Forbidden energy/power keys, units, RAPL, NVML, tok/J, camelCase, Cf/Mn, fullwidth (27) ---
    ({"mj_per_tok": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"j_per_tok": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"uJ_per_tok": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"mean_watts": 45}, "FORBIDDEN_ENERGY_KEY"),
    ({"pkg_w": 15}, "FORBIDDEN_ENERGY_KEY"),
    ({"total_j": 100}, "FORBIDDEN_ENERGY_KEY"),
    ({"pwr": 25}, "FORBIDDEN_ENERGY_KEY"),
    ({"max_45w": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"45w": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"130w_psu": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"t_d_p": 45}, "FORBIDDEN_ENERGY_KEY"),
    ({"p.o.w.e.r": 45}, "FORBIDDEN_ENERGY_KEY"),
    ({"totalenergyreduction": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"avgpowermw": 45000}, "FORBIDDEN_ENERGY_KEY"),
    ({"power_mw": 45000}, "FORBIDDEN_ENERGY_KEY"),
    ({"kwh": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"tdp": 45}, "FORBIDDEN_ENERGY_KEY"),
    ({"avg_power": 30}, "FORBIDDEN_ENERGY_KEY"),
    ({"wattage": 45}, "FORBIDDEN_ENERGY_KEY"),
    ({"rapl_pkg_uj": 12000}, "FORBIDDEN_ENERGY_KEY"),
    ({"intel_rapl": 14}, "FORBIDDEN_ENERGY_KEY"),
    ({"nvml_power_mw": 45000}, "FORBIDDEN_ENERGY_KEY"),
    ({"tok_per_j": 1200}, "FORBIDDEN_ENERGY_KEY"),
    ({"\uff4d\uff4a_per_tok": 1}, "FORBIDDEN_ENERGY_KEY"),
    ({"p\u0301ower_draw": 45}, "FORBIDDEN_ENERGY_KEY"),
    ({"p\u200bower": 45}, "FORBIDDEN_ENERGY_KEY"),
    ({"totalEnergy": 10}, "FORBIDDEN_ENERGY_KEY"),
    # --- Non-ASCII homoglyph / Cyrillic / Greek / Armenian look-alike bypasses (6) ---
    ({"note": "5 \u051d"}, "NON_ASCII_POLICY_TEXT"),
    ({"\u0435nergy": 1}, "NON_ASCII_POLICY_TEXT"),
    ({"note": "3 \u043a\u0412\u0442"}, "NON_ASCII_POLICY_TEXT"),
    ({"note": "45.2 \u03c9"}, "NON_ASCII_POLICY_TEXT"),
    ({"note": "\u051datt"}, "NON_ASCII_POLICY_TEXT"),
    ({"p\u043ewer": 45}, "NON_ASCII_POLICY_TEXT"),
    # --- Forbidden energy/power values: bare units, SI/e-notation/sep/Cf/Mn, RAPL, NVML, nvidia-smi, tok/J, wattage, prose (41) ---
    ({"metric_unit": "W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"unit": {"name": "kW"}}, "FORBIDDEN_ENERGY_VAL"),
    ({"units_used": "mW"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "W?"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "TDP"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "watt-hour"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "[kW]"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "\u00b5W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "mJ/tok"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "joules"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "45.2 W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "45W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "5 GW"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "5 TW"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "5 pW"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "5 kilo watts"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "5 m W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "15 watthours"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "45 Whr"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "cap_45_w"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "45_watts"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "draw_45w"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "W_45"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "5\u2013W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "12\u00b7W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "45.2\u00d7W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "15 TDP"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "45.2\u200bW"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "45.2\ufeffW"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "W: 45.2"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "3.9e2 W"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "0.001 J/tok"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "0.5 kWh"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "\uff11\uff12\uff37"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "1200 tok/J"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "500 tokens/mJ"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "peak laptop wattage"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "intel-rapl package counter 14"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "nvmlDeviceGetPowerUsage 45000"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "nvidia-smi --query-gpu=power.draw"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "W/token"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "millijoules per token"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "intel_rapl"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "nvidia_smi"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "energy per token"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "nvmlDeviceGetPowerManagementLimit = 220"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "nvmlDeviceGetTotalEnergyConsumption"}, "FORBIDDEN_ENERGY_VAL"),
    (
        {"note": "nvidia-smi --query-gpu=timestamp,name,pci.bus_id,driver_version,pstate,temperature.gpu,power.draw"},
        "FORBIDDEN_ENERGY_VAL",
    ),
    ({"note": "J per generated token"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "joules_per_token"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "tok_per_mwh"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "100 W/ token"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "100 W/ s"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "forty-five watts"}, "FORBIDDEN_ENERGY_VAL"),
    ({"note": "energy: 12"}, "FORBIDDEN_ENERGY_VAL"),
)

# Full in-repo 60-case benign thermal/chatter/identifier/non-energy telemetry control corpus
BENIGN_TELEMETRY_CONTROLS: tuple[dict, ...] = (
    {"temp_c": 65},
    {"temp_c": 70, "power_band": "ac"},
    {"temp_c": 78, "power_band": "battery"},
    {"temp_c": 85, "power_band": "unknown"},
    {"metric_unit": "deg_c"},
    {"note": "5 ms"},
    {"note": "70 C"},
    {"note": "78\u00b0C"},
    {"note": "70/78/85 C knees"},
    {"note": "5 deg C deadband"},
    {"note": "135/2"},
    {"note": "45.0%"},
    {"note": "0.5 mm"},
    {"note": "grad_W_q"},
    {"note": "cpu_jiffies_total"},
    {"note": "129,279.00 tok/s"},
    {"note": "469.41 us/tok"},
    {"note": "8.113 MiB"},
    {"note": "sm_86"},
    {"note": "R10-TAG-61"},
    {"note": "J2000"},
    {"note": "J2000.0"},
    {"note": "worker W10"},
    {"note": "2024-W05"},
    {"note": "sprint-W12"},
    {"note": "node-w10"},
    {"note": "W-2"},
    {"note": "W12"},
    {"note": "kW12"},
    {"note": "bench w/ perf counters"},
    {"note": "taskset -c 3 w/ 5 reps"},
    {"note": "12 ms/tok"},
    {"note": "sm_clock 2100 MHz"},
    {"note": "0.9 V"},
    {"note": "fan1 3400 RPM"},
    {"note": "fan2 3300 RPM"},
    {"note": "nvidia-smi memory.used 0 MiB"},
    {"note": "nvidia-smi temperature.gpu 68 C"},
    {"note": "nvml temperature 72 C"},
    {"note": "hysteresis_switches 0"},
    {"note": "bangbang_switches 39"},
    {"note": "gear 2 HIGH_GUARD"},
    {"note": "gear 3 CLAMP_GUARD"},
    {"note": "throttle_stall_count 0"},
    {"note": "jitter_p99 420 us"},
    {"note": "screenpad 3840x1100"},
    {"note": "oled eDP-1 3840x2160"},
    {"note": "loadavg 1.25 / 16 cores"},
    {"note": "ram_avail 24512 MiB"},
    {"note": "TEMPERATURE_AND_CHATTER_ONLY"},
    {"tokens_per_window": 1024},
    {"tokens_per_worker": 512},
    {"tokens_per_job": 4096},
    {"nvml_warnings": 0},
    {"wrapLimit": 64},
    {"scrapLog": 0},
    {"note": "w/ tokens"},
    {"note": "3 w/o pinning"},
    {"note": "W = 4"},
    {"note": "wattage design review"},
)


class TestAletheionHypersphericExoskeletonR5(unittest.TestCase):
    # ------------------------------------------------------------------
    # 0. AST Purity: Zero Float Literals & Zero Bare Asserts Across All 3 Modules
    # ------------------------------------------------------------------
    def test_01_ast_zero_floats_and_zero_bare_asserts(self) -> None:
        for fname in ("hyperspheric-hud.py", "aletheion_hysteresis_governor.py", "aletheion_exoskeleton_plugins.py"):
            src = (BIN_DIR / fname).read_text(encoding="utf-8")
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Assert):
                    self.fail(f"Bare assert found in {fname}")
                if isinstance(node, ast.Constant) and type(node.value) is float:
                    self.fail(f"Float literal {node.value!r} found in {fname}")

    # ------------------------------------------------------------------
    # 1. bin/hyperspheric-hud.py: Guards, Unified NFKC+Cf+Mn Policy, RAG & CLI
    # ------------------------------------------------------------------
    def test_02_hud_primitives_and_nfkc_cf_mn_energy_policy_guards(self) -> None:
        self.assertEqual(hud.check_nonneg_int(0, "z"), 0)
        self.assertEqual(hud.check_nonneg_int(hud.MAX_INT_ABS, "m"), hud.MAX_INT_ABS)
        for bad in (-1, True, 1.5, hud.MAX_INT_ABS + 1, "1"):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.check_nonneg_int(bad, "x")
            self.assertEqual(cm.exception.code, "BAD_NONNEG_INT")

        self.assertEqual(hud.fmt_pct_tenths(0, 0), "0.0%")
        self.assertEqual(hud.fmt_pct_tenths(1, 2), "50.0%")
        self.assertEqual(hud.fmt_pct_tenths(29227, 64951), "44.9%")

        # Legitimate thermal scalars, identifiers (R2), & allowlisted power_band pass cleanly
        hud.validate_no_floats_or_energy_claims(
            {
                "ok": [
                    1,
                    "a",
                    True,
                    None,
                    "5 ms",
                    "70 C",
                    "78\u00b0C",
                    "70/78/85 C knees",
                    "5 deg C deadband",
                    "135/2",
                    "45.0%",
                    "0.5 mm",
                    "grad_W_q",
                    "cpu_jiffies_total",
                    "129,279.00 tok/s",
                    "469.41 us/tok",
                    "8.113 MiB",
                    "sm_86",
                    "R10-TAG-61",
                    "J2000",
                    "J2000.0",
                    "worker W10",
                    "2024-W05",
                    "sprint-W12",
                    "node-w10",
                    "W-2",
                    "W12",
                    "kW12",
                    "bench w/ perf counters",
                    "taskset -c 3 w/ 5 reps",
                    "12 ms/tok",
                    "sm_clock 2100 MHz",
                    "0.9 V",
                ],
                "temp_c": 65,
                "power_band": "ac",
                "metric_unit": "deg_c",
            },
            max_depth=4,
        )
        hud.validate_no_floats_or_energy_claims([[[[1]]]], max_depth=4)
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_no_floats_or_energy_claims({"ok": 1}, max_depth=None)  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, "BAD_NONNEG_INT")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_no_floats_or_energy_claims([[[[1]]]], max_depth=3)
        self.assertEqual(cm.exception.code, "JSON_DEPTH")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_no_floats_or_energy_claims({"f": 0.5})
        self.assertEqual(cm.exception.code, "FLOAT_FORBIDDEN")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_no_floats_or_energy_claims({1: "x"})
        self.assertEqual(cm.exception.code, "BAD_KEY")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_no_floats_or_energy_claims({"t": (1, 2)})
        self.assertEqual(cm.exception.code, "BAD_JSON_TYPE")

        # Asymmetric forbidden key checks (compact regex, value regex on max_45w/130w_psu, token set on pkg_w/pwr, camelCase, Cf/Mn)
        for bad_ek in (
            "mj_per_tok",
            "j_per_tok",
            "uJ_per_tok",
            "mean_watts",
            "pkg_w",
            "total_j",
            "pwr",
            "max_45w",
            "45w",
            "130w_psu",
            "t_d_p",
            "p.o.w.e.r",
            "totalenergyreduction",
            "avgpowermw",
            "power_mw",
            "kwh",
            "tdp",
            "avg_power",
            "\uff4d\uff4a_per_tok",
            "p\u0301ower_draw",
            "e\u0301nergy_j",
            "p\u200bower",
            "totalEnergy",
        ):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.validate_no_floats_or_energy_claims({bad_ek: 1})
            self.assertEqual(cm.exception.code, "FORBIDDEN_ENERGY_KEY")

        for bad_pb in (123, "quiet_45w", {"note": "45.2 W"}, ["ac"]):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.validate_no_floats_or_energy_claims({"power_band": bad_pb})
            self.assertEqual(cm.exception.code, "BAD_POWER_BAND")

        # Non-ASCII homoglyph / Cyrillic / Greek look-alikes rejected fail-closed
        for bad_homoglyph in ({"note": "5 \u051d"}, {"\u0435nergy": 1}, {"note": "3 \u043a\u0412\u0442"}, {"note": "45.2 \u03c9"}, {"note": "\u051datt"}):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.validate_no_floats_or_energy_claims(bad_homoglyph)
            self.assertEqual(cm.exception.code, "NON_ASCII_POLICY_TEXT")

        # Bare units (top-level, nested under unit dict), glued/SI/separator/e-notation/punctuation & prose claims (R1)
        for bad_val_tree in (
            {"metric_unit": "W"},
            {"unit": {"name": "kW"}},
            {"units_used": "mW"},
            {"note": "W"},
            {"note": "W?"},
            {"note": "TDP"},
            {"note": "watt-hour"},
            {"note": "[kW]"},
            {"note": "\u00b5W"},
            {"note": "mJ/tok"},
            {"note": "joules"},
            {"note": "45.2 W"},
            {"note": "45.2 W."},
            {"note": "45.2W!"},
            {"note": "45W"},
            {"note": "5 GW"},
            {"note": "5 TW"},
            {"note": "5 pW"},
            {"note": "5 PW"},
            {"note": "5 kilo watts"},
            {"note": "5 kilo-watts"},
            {"note": "5 m W"},
            {"note": "15 watthours"},
            {"note": "15 watt hours"},
            {"note": "15 watt-hour"},
            {"note": "45 Whr"},
            {"note": "cap_45_w"},
            {"note": "45_watts"},
            {"note": "limit_45_w"},
            {"note": "draw_45w"},
            {"note": "W_45"},
            {"note": "130w_psu"},
            {"note": "max_45w"},
            {"note": "45w"},
            {"note": "5\u2013W"},
            {"note": "12\u00b7W"},
            {"note": "45.2\u2219W"},
            {"note": "45.2\u00d7W"},
            {"note": "15 TDP"},
            {"note": "TDP 15"},
            {"note": "45.2\u200bW"},
            {"note": "45.2 k\u200bW"},
            {"note": "45.2\ufeffW"},
            {"note": "45.2 kilowatts"},
            {"note": "45 milliwatts"},
            {"note": "1.2 megawatts"},
            {"note": "12.5 kilojoules"},
            {"note": "45.2-W"},
            {"note": "45.2 [W]"},
            {"note": "45.2[W] drain"},
            {"note": "W: 45.2"},
            {"note": "W=45.2"},
            {"note": "W: 45.2 drain"},
            {"note": "J: 5"},
            {"note": "3.9e2 W"},
            {"note": "1.5E-3W"},
            {"note": "0.001 J/tok"},
            {"note": "0.5 kWh"},
            {"note": "measured 45.2 mW"},
            {"note": "12.5 joules"},
            {"note": "180 \u00b5W"},
            {"note": "\uff11\uff12\uff37"},
            {"note": "energy use dropped"},
            {"note": "power savings"},
            {"note": "joules per token"},
            {"note": "MJ per token"},
            {"note": "70% less energy"},
            {"note": "70 percent less power"},
            {"note": "achieved energy reduction"},
        ):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.validate_no_floats_or_energy_claims(bad_val_tree)
            self.assertEqual(cm.exception.code, "FORBIDDEN_ENERGY_VAL")

        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud._check_safe_path(Path("a\x00b"), "p")
        self.assertEqual(cm.exception.code, "UNSAFE_PATH")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud._check_safe_path(Path("../secret"), "p")
        self.assertEqual(cm.exception.code, "UNSAFE_PATH")

    def test_03_hud_web_board_hooks_rag_validation_and_cli(self) -> None:
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.summarize_epistemic_web_index([])
        self.assertEqual(cm.exception.code, "BAD_INDEX_ROOT")
        base_web = {
            "index_sha256": "a" * 64,
            "node_count": 0,
            "total_cross_org_edges": 0,
            "total_historical_edges": 0,
            "operator_taxonomy_count": 1,
            "obstruction_taxonomy_count": 1,
            "org_counts": {"org_a": 1},
            "cross_org_bridge_matrix": {},
        }
        s_zero = hud.summarize_epistemic_web_index(base_web)
        self.assertEqual(s_zero["historical_interposition_share_q"], "0/1")
        self.assertEqual(s_zero["bridge_pair_density_q"], "0/1")
        self.assertEqual(s_zero["mean_cross_org_degree_q"], "0/1")

        mix_web = copy.deepcopy(base_web)
        mix_web["org_counts"] = {"org_a": 1, "org_b": 1, "org_c": 1}
        mix_web["cross_org_bridge_matrix"] = {"pos": 5, "zero": 0}
        self.assertEqual(hud.summarize_epistemic_web_index(mix_web)["active_org_bridge_pairs"], 1)
        for bad_bm, code in [
            ({1: 5}, "BAD_BRIDGE_KEY"),
            ({"bool_t": True}, "BAD_NONNEG_INT"),
            ({"bad_str": "x"}, "BAD_NONNEG_INT"),
        ]:
            w_bm = copy.deepcopy(base_web)
            w_bm["cross_org_bridge_matrix"] = bad_bm
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.summarize_epistemic_web_index(w_bm)
            self.assertEqual(cm.exception.code, code)

        for bad_org, code in [
            ({"": 1}, "BAD_ORG_KEY"),
            ({1: 1}, "BAD_ORG_KEY"),
            ({("a",): 1}, "BAD_ORG_KEY"),
            ({"org_a": -1}, "BAD_NONNEG_INT"),
            ({"org_a": True}, "BAD_NONNEG_INT"),
            ({"org_a": "x"}, "BAD_NONNEG_INT"),
        ]:
            w_org = copy.deepcopy(base_web)
            w_org["org_counts"] = bad_org
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.summarize_epistemic_web_index(w_org)
            self.assertEqual(cm.exception.code, code)

        # Valid 1-char org key with zero count passes exact boundary
        w_org_ok = copy.deepcopy(base_web)
        w_org_ok["org_counts"] = {"a": 0}
        self.assertEqual(hud.summarize_epistemic_web_index(w_org_ok)["org_bucket_count"], 1)

        # B4: Reject non-hex, uppercase, short, non-str index_sha256
        for k, bad_val, code in [
            ("org_counts", {}, "BAD_ORG_COUNTS"),
            ("org_counts", ["org_a"], "BAD_ORG_COUNTS"),
            ("cross_org_bridge_matrix", [], "BAD_BRIDGE_MATRIX"),
            ("index_sha256", "short", "BAD_INDEX_SHA"),
            ("index_sha256", "z" * 64, "BAD_INDEX_SHA"),
            ("index_sha256", "A" * 64, "BAD_INDEX_SHA"),
            ("index_sha256", 123, "BAD_INDEX_SHA"),
        ]:
            w = copy.deepcopy(base_web)
            w[k] = bad_val
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.summarize_epistemic_web_index(w)
            self.assertEqual(cm.exception.code, code)

        # B2: Board lines container & element type guards (no raw AttributeError / TypeError)
        for bad_lines in (None, "abc", 123):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.summarize_board_and_members(bad_lines)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_BOARD_LINES")
        for bad_elem in ([123], [None]):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.summarize_board_and_members(bad_elem)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_BOARD_LINE_TYPE")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.summarize_board_and_members([], None, None)  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, "BAD_POLOIDAL_ROLES")

        sw = hud.summarize_board_and_members(
            ["", json.dumps({"agent": "worker", "text": "ok"})],
            {"members": [{"name": "a", "state": "working"}, {"name": "b", "state": "waiting"}, "non_dict"]},
        )
        self.assertEqual((sw["board_messages"], sw["members_total"], sw["members_working"]), (1, 3, 1))
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.summarize_board_and_members(["{bad json"])
        self.assertEqual(cm.exception.code, "BAD_BOARD_JSONL")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.summarize_board_and_members(["[]"])
        self.assertEqual(cm.exception.code, "BAD_BOARD_REC")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.summarize_board_and_members([], "not_dict")  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, "BAD_MEMBERS_ROOT")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.summarize_board_and_members([], {"members": "not_list"})
        self.assertEqual(cm.exception.code, "BAD_MEMBERS_LIST")

        self.assertEqual(hud.inspect_contention_hook(None)["status"], "not_provided")
        self.assertEqual(hud.inspect_contention_hook({"environment": {"contended": False}})["power_band"], "unknown")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.inspect_contention_hook([])  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, "BAD_CONTENTION_ROOT")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.inspect_contention_hook({"environment": []})
        self.assertEqual(cm.exception.code, "BAD_CONTENTION_ENV")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.inspect_contention_hook({"environment": {"contended": "yes"}})
        self.assertEqual(cm.exception.code, "BAD_CONTENDED_FLAG")

        self.assertEqual(hud.inspect_rag_sqlite_hook(None)["status"], "not_wired_yet")
        for bad_p in ("/tmp/rag.sqlite", 123):
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.inspect_rag_sqlite_hook(bad_p)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_RAG_PATH")
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.inspect_rag_sqlite_hook(Path("x.sqlite"), query=123)  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, "BAD_RAG_QUERY")
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            self.assertEqual(hud.inspect_rag_sqlite_hook(tdp / "nope.sqlite")["status"], "missing_db")

            min_db = tdp / "min.sqlite"
            c_min = sqlite3.connect(min_db)
            c_min.execute("CREATE TABLE nodes (id TEXT)")
            c_min.execute("INSERT INTO nodes VALUES ('n0')")
            c_min.commit()
            c_min.close()
            r_min = hud.inspect_rag_sqlite_hook(min_db, query="panini")
            self.assertEqual((r_min["status"], r_min["nodes_rows"], r_min["query_matches"]), ("wired", 1, []))

            dbp = tdp / "rag.sqlite"
            conn = sqlite3.connect(dbp)
            conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT INTO meta VALUES ('schema_version', 'aletheia.epistemic_rag_graph.v1')")
            conn.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY, org TEXT NOT NULL, is_verified_cert INTEGER NOT NULL)")
            conn.execute("INSERT INTO nodes VALUES ('n1', 'org_a', 1), ('n2', 'org_b', 0)")
            conn.execute("CREATE TABLE edges (src TEXT, dst TEXT, edge_type TEXT)")
            conn.execute("INSERT INTO edges VALUES ('n1', 'n2', 'PROVES_OPERATOR'), ('n2', 'n1', 'BRIDGES')")
            conn.execute("CREATE TABLE dense_embeddings (node_id TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO dense_embeddings VALUES ('n1'), ('n2')")
            conn.execute("CREATE VIRTUAL TABLE fts_chunks USING fts5(node_id UNINDEXED, title)")
            conn.execute("INSERT INTO fts_chunks VALUES ('n1', 'panini sivasutra c1p'), ('n2', 'chokwe sona cycle')")
            conn.commit()
            conn.close()
            r_ok = hud.inspect_rag_sqlite_hook(dbp, query="panini")
            self.assertEqual(
                (r_ok["status"], r_ok["nodes_rows"], r_ok["edges_rows"], r_ok["verified_cert_nodes"], r_ok["org_buckets"], r_ok["dense_embeddings_rows"], r_ok["query_matches"]),
                ("wired", 2, 2, 1, 2, 2, ["n1"]),
            )
            self.assertEqual(hud.inspect_rag_sqlite_hook(dbp, query=None)["query_matches"], [])

            bad_db = tdp / "corrupt.sqlite"
            bad_db.write_bytes(b"not a sqlite database")
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.inspect_rag_sqlite_hook(bad_db)
            self.assertEqual(cm.exception.code, "BAD_RAG_SQLITE")

            web_p = tdp / "web.json"
            web_p.write_text(json.dumps({**base_web, "node_count": 777, "total_cross_org_edges": 64951, "total_historical_edges": 29227, "org_counts": {"a": 1, "b": 2}, "cross_org_bridge_matrix": {"ab": 5}}), encoding="utf-8")
            brd_p = tdp / "board.jsonl"
            brd_p.write_text(json.dumps({"agent": "custom-cartographer", "text": "[done] ok"}) + "\n", encoding="utf-8")
            mem_p = tdp / "members.json"
            mem_p.write_text(json.dumps({"members": [{"name": "a", "state": "working"}]}), encoding="utf-8")
            cnt_p = tdp / "cont.json"
            cnt_p.write_text(json.dumps({"environment": {"contended": False, "power_band": "ac"}}), encoding="utf-8")

            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc = hud.main([
                    "--once", "--json", "--web-index", str(web_p),
                    "--board", str(brd_p), "--members", str(mem_p),
                    "--poloidal-roles", "custom-cartographer",
                    "--contention-json", str(cnt_p),
                    "--rag-db", str(dbp), "--rag-query", "panini",
                ])
            self.assertEqual(rc, 0)
            snap_out = json.loads(buf.getvalue())
            self.assertEqual(snap_out["rag_hook"]["query_matches"], ["n1"])
            self.assertEqual(snap_out["board_dynamics"]["poloidal_messages"], 1)
            self.assertEqual(snap_out["captured_unix_s"], 0)

            # A6: Fail closed when --once or --web-index is passed without the other
            for partial_args in (["--once"], ["--web-index", str(web_p)]):
                err_p = io.StringIO()
                with mock.patch("sys.stderr", err_p):
                    self.assertEqual(hud.main(partial_args), 2)
                self.assertIn("BAD_CLI_MODE", err_p.getvalue())

            buf_def = io.StringIO()
            with mock.patch("sys.stdout", buf_def):
                self.assertEqual(hud.main([]), 0)
            self.assertEqual(json.loads(buf_def.getvalue())["snapshot_sha256"], hud.run_selftest()["snapshot_sha256"])

            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud._load_json_file(tdp / "missing.json", "web_index")
            self.assertEqual(cm.exception.code, "READ_OR_JSON_ERR")
            corrupt_json = tdp / "corrupt.json"
            corrupt_json.write_text("{broken", encoding="utf-8")
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud._load_json_file(corrupt_json, "web_index")
            self.assertEqual(cm.exception.code, "READ_OR_JSON_ERR")

            buf_sp = io.StringIO()
            with mock.patch("sys.stdout", buf_sp):
                rc_sp = hud.main(["--self-test", "--screenpad"])
            self.assertEqual(rc_sp, 0)
            self.assertIn("ALETHEION S^3 HYPERSPHERIC HUD", buf_sp.getvalue())

            err_buf = io.StringIO()
            with mock.patch("sys.stderr", err_buf):
                rc_err = hud.main(["--once", "--web-index", str(tdp / "missing.json")])
            self.assertEqual(rc_err, 2)
            self.assertIn("READ_OR_JSON_ERR", err_buf.getvalue())

            # R3: Non-UTF-8 --board returns exit code 2 (no uncaught UnicodeDecodeError)
            bad_brd = tdp / "bad_board.jsonl"
            bad_brd.write_bytes(b"\xff\xfe\x00invalid utf8")
            err_brd = io.StringIO()
            with mock.patch("sys.stderr", err_brd):
                self.assertEqual(hud.main(["--once", "--web-index", str(web_p), "--board", str(bad_brd)]), 2)
            self.assertIn("READ_OR_DECODE_ERR", err_brd.getvalue())
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud._load_text_lines(bad_brd, "board")
            self.assertEqual(cm.exception.code, "READ_OR_DECODE_ERR")

        # B3: Snapshot root + nested section schema validation WITH recomputed snapshot_sha256
        snap = hud.run_selftest()
        hud.validate_hud_snapshot(snap)
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot([])
        self.assertEqual(cm.exception.code, "BAD_SNAP_ROOT")
        for k in list(snap.keys()):
            c = copy.deepcopy(snap)
            del c[k]
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.validate_hud_snapshot(c)
            self.assertEqual(cm.exception.code, "MISSING_KEY")
        c_extra = copy.deepcopy(snap)
        c_extra["unvalidated_extra"] = "sneaky"
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_extra))
        self.assertEqual(cm.exception.code, "EXTRA_KEY")
        for k, bad_val, code in [
            ("schema", "bad", "BAD_SCHEMA"),
            ("zero_floats", False, "BAD_ZERO_FLOATS"),
            ("telemetry_scope_policy", "CLAIMED", "BAD_SCOPE_POLICY"),
            ("snapshot_sha256", 123, "SNAP_SHA_MISMATCH"),
            ("snapshot_sha256", "0" * 64, "SNAP_SHA_MISMATCH"),
            ("snapshot_sha256", "\u00b0" * 64, "SNAP_SHA_MISMATCH"),
        ]:
            c = copy.deepcopy(snap)
            c[k] = bad_val
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.validate_hud_snapshot(c)
            self.assertEqual(cm.exception.code, code)

        # Re-signed nested section forgeries MUST fail closed
        for sec in ("hyperspheric_web", "board_dynamics", "contention_hook", "rag_hook"):
            c = copy.deepcopy(snap)
            c[sec] = "BAD_STRING_SECTION"
            with self.assertRaises(hud.HypersphericHudError) as cm:
                hud.validate_hud_snapshot(_resign_hud_snap(c))
            self.assertEqual(cm.exception.code, "BAD_SECTION_TYPE")

        c_miss = copy.deepcopy(snap)
        del c_miss["hyperspheric_web"]["node_count"]
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_miss))
        self.assertEqual(cm.exception.code, "MISSING_SECTION_KEY")

        c_str = copy.deepcopy(snap)
        c_str["board_dynamics"]["poloidal_share_pct"] = 50
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_str))
        self.assertEqual(cm.exception.code, "BAD_SECTION_STR")

        c_str2 = copy.deepcopy(snap)
        del c_str2["board_dynamics"]["poloidal_share_pct"]
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_str2))
        self.assertEqual(cm.exception.code, "BAD_SECTION_STR")

        c_hex = copy.deepcopy(snap)
        c_hex["hyperspheric_web"]["index_sha256"] = "z" * 64
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_hex))
        self.assertEqual(cm.exception.code, "BAD_INDEX_SHA")

        c_cnt = copy.deepcopy(snap)
        c_cnt["contention_hook"]["contended"] = "no"
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_cnt))
        self.assertEqual(cm.exception.code, "BAD_CONTENDED_FLAG")

        c_rag1 = copy.deepcopy(snap)
        c_rag1["rag_hook"]["edge_type_counts"] = []
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_rag1))
        self.assertEqual(cm.exception.code, "BAD_RAG_EDGE_TYPES")

        c_rag2 = copy.deepcopy(snap)
        c_rag2["rag_hook"]["query_matches"] = {}
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_rag2))
        self.assertEqual(cm.exception.code, "BAD_RAG_MATCHES")

        c_rag3 = copy.deepcopy(snap)
        c_rag3["rag_hook"]["edge_type_counts"] = {"PROVES": -1}
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_rag3))
        self.assertEqual(cm.exception.code, "BAD_NONNEG_INT")

        c_rag4 = copy.deepcopy(snap)
        c_rag4["rag_hook"]["query_matches"] = [123]
        with self.assertRaises(hud.HypersphericHudError) as cm:
            hud.validate_hud_snapshot(_resign_hud_snap(c_rag4))
        self.assertEqual(cm.exception.code, "BAD_RAG_MATCH_ITEM")

    # ------------------------------------------------------------------
    # 2. bin/aletheion_hysteresis_governor.py: Policy Parity, B2 Guards & Tamper
    # ------------------------------------------------------------------
    def test_04_thermal_governor_primitives_policy_and_operators(self) -> None:
        self.assertEqual(gov.check_frac(gov.MAX_INT_ABS, "m"), Fraction(gov.MAX_INT_ABS, 1))
        self.assertEqual(gov.check_frac(-gov.MAX_INT_ABS, "m"), Fraction(-gov.MAX_INT_ABS, 1))
        self.assertEqual(gov.check_frac(Fraction(gov.MAX_INT_ABS, gov.MAX_INT_ABS - 1), "m"), Fraction(gov.MAX_INT_ABS, gov.MAX_INT_ABS - 1))
        for bad, code in [
            (True, "BAD_FRAC"),
            (1.5, "BAD_FRAC"),
            ("1", "BAD_FRAC"),
            (gov.MAX_INT_ABS + 1, "INT_RANGE"),
            (-(gov.MAX_INT_ABS + 1), "INT_RANGE"),
            (Fraction(gov.MAX_INT_ABS + 1, 1), "FRAC_RANGE"),
            (Fraction(1, gov.MAX_INT_ABS + 1), "FRAC_RANGE"),
        ]:
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.check_frac(bad, "x")
            self.assertEqual(cm.exception.code, code)

        self.assertEqual(gov.check_pos_int(1, "p"), 1)
        self.assertEqual(gov.check_pos_int(gov.MAX_INT_ABS, "p"), gov.MAX_INT_ABS)
        for bad in (0, -1, True, gov.MAX_INT_ABS + 1):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.check_pos_int(bad, "p")
            self.assertEqual(cm.exception.code, "BAD_POS_INT")

        # Unified B1 + R1/R2 policy checks in governor
        gov.validate_json_tree_no_floats(
            {"a": [1, "s", True, None, "J2000", "2024-W05", "worker W10", "W12", "taskset -c 3 w/ 5 reps"], "power_band": "ac", "note": "70/78/85 C knees (70\u00b0C)"},
            max_depth=4,
        )
        gov.validate_json_tree_no_floats([[[[1]]]], max_depth=4)
        for bad_md in (None, -1, True, gov.MAX_INT_ABS + 1):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_json_tree_no_floats({"a": 1}, max_depth=bad_md)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_MAX_DEPTH")
        gov.validate_json_tree_no_floats(1, max_depth=0)
        gov.validate_json_tree_no_floats(1, max_depth=gov.MAX_INT_ABS)
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_json_tree_no_floats([[[[1]]]], max_depth=3)
        self.assertEqual(cm.exception.code, "JSON_DEPTH")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_json_tree_no_floats({"f": 0.1})
        self.assertEqual(cm.exception.code, "FLOAT_FORBIDDEN")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_json_tree_no_floats({1: "x"})
        self.assertEqual(cm.exception.code, "BAD_KEY")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_json_tree_no_floats({"t": (1, 2)})
        self.assertEqual(cm.exception.code, "BAD_JSON_TYPE")
        for bad_pb in (123, "bad_band"):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_json_tree_no_floats({"power_band": bad_pb})
            self.assertEqual(cm.exception.code, "BAD_POWER_BAND")
        for bad_ek in ("t_d_p", "p.o.w.e.r", "pkg_w", "total_j", "pwr", "max_45w", "130w_psu", "j_per_tok", "mean_watts", "totalenergyreduction", "avgpowermw", "p\u0301ower_mw"):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_json_tree_no_floats({bad_ek: 1})
            self.assertEqual(cm.exception.code, "FORBIDDEN_ENERGY_KEY")
        for bad_homoglyph in ({"note": "5 \u051d"}, {"\u0435nergy": 1}):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_json_tree_no_floats(bad_homoglyph)
            self.assertEqual(cm.exception.code, "NON_ASCII_POLICY_TEXT")
        for bad_u in ({"unit": "W"}, {"unit": {"name": "kW"}}, {"note": "W"}, {"note": "TDP"}, {"note": "watt-hour"}):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_json_tree_no_floats(bad_u)
            self.assertEqual(cm.exception.code, "FORBIDDEN_ENERGY_VAL")
        for bad_ev in ("45.2 W", "5 GW", "5 TW", "5 pW", "5 kilo watts", "5 m W", "15 watthours", "45 Whr", "cap_45_w", "45_watts", "limit_45_w", "draw_45w", "W_45", "5\u2013W", "12\u00b7W", "45.2\u00d7W", "15 TDP", "45.2\u200bW", "45.2 kilowatts", "W: 45.2", "3.9e2 W", "energy use dropped", "joules per token", "MJ per token", "70% less energy"):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_json_tree_no_floats({"note": bad_ev})
            self.assertEqual(cm.exception.code, "FORBIDDEN_ENERGY_VAL")

        self.assertEqual(gov.petra_stepped_filter_q([50], 2, 2), [Fraction(50, 1)])
        for bad_tr in ([], "50", None):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.petra_stepped_filter_q(bad_tr, 2, 2)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "EMPTY_TRACE")
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.simulate_hysteresis_vs_bangbang(bad_tr)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "EMPTY_TRACE")
        for k1, k2 in ((1, 2), (2, 1)):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.petra_stepped_filter_q([50, 60], k1, k2)
            self.assertEqual(cm.exception.code, "BAD_CHAMBER_K")

        # B2: validate_knee_ladder container type guards (no raw TypeError on None)
        for bad_u, bad_d in ((None, [65]), ([70], None), (None, None)):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_knee_ladder(bad_u, bad_d)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_KNEES_TYPE")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_knee_ladder([], [])
        self.assertEqual(cm.exception.code, "BAD_KNEES_LEN")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_knee_ladder([Fraction(70, 1)], [Fraction(65, 1), Fraction(70, 1)])
        self.assertEqual(cm.exception.code, "BAD_KNEES_LEN")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_knee_ladder([Fraction(70, 1)], [Fraction(70, 1)])
        self.assertEqual(cm.exception.code, "NONPOS_DEADBAND")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_knee_ladder([Fraction(70, 1), Fraction(70, 1)], [Fraction(60, 1), Fraction(65, 1)])
        self.assertEqual(cm.exception.code, "NON_MONO_KNEES")
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_knee_ladder([Fraction(70, 1), Fraction(80, 1)], [Fraction(65, 1), Fraction(65, 1)])
        self.assertEqual(cm.exception.code, "NON_MONO_KNEES")

        for bad_g in (-1, 4, True):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.step_hysteresis_gear(bad_g, Fraction(70, 1), gov.DEFAULT_UP_KNEES, gov.DEFAULT_DN_KNEES)
            self.assertEqual(cm.exception.code, "BAD_GEAR")

        for k, uy, um, al, code in [
            (0, 1, 2, 0, "NONPOS_PARAM"),
            (1, 0, 2, 0, "NONPOS_PARAM"),
            (1, 2, 2, 0, "NO_SLIP"),
            (1, 1, 2, Fraction(-1, 10), "BAD_ALPHA"),
            (1, 1, 2, Fraction(11, 10), "BAD_ALPHA"),
        ]:
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.dougong_deadband_loop_q(k, uy, um, al)
            self.assertEqual(cm.exception.code, code)

    def test_05_thermal_governor_cert_tamper_monkeypatch_and_cli(self) -> None:
        cert = gov.certify_thermal_governor()
        self.assertTrue(cert["all_passed"])
        self.assertEqual(cert["g1_zero_chatter"]["metrics"]["bangbang_switches"], 39)
        self.assertEqual(cert["g1_zero_chatter"]["metrics"]["hysteresis_switches"], 0)
        self.assertEqual(cert["g2_glitch_and_ramp"]["glitch"]["hysteresis_switches"], 0)
        self.assertEqual(cert["g3_dougong_loop"]["coulomb"]["e_diss_shoelace"], "100/1")

        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_governor_certificate([])
        self.assertEqual(cm.exception.code, "BAD_CERT_ROOT")
        for k in list(cert.keys()):
            c = copy.deepcopy(cert)
            del c[k]
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_governor_certificate(c)
            self.assertEqual(cm.exception.code, "MISSING_KEY")
        c_ex = copy.deepcopy(cert)
        c_ex["extra_field"] = 1
        with self.assertRaises(gov.ThermalGovError) as cm:
            gov.validate_governor_certificate(c_ex)
        self.assertEqual(cm.exception.code, "EXTRA_KEY")
        for k, bad_v, code in [
            ("schema", "bad", "BAD_SCHEMA"),
            ("zero_floats", False, "BAD_ZERO_FLOATS"),
            ("telemetry_scope_policy", "BAD", "BAD_SCOPE_POLICY"),
            ("g1_zero_chatter", [], "BAD_SECTION"),
            ("all_passed", False, "ALL_PASSED_FALSE"),
            ("payload_sha256", 123, "PAYLOAD_SHA_MISMATCH"),
            ("payload_sha256", "0" * 64, "PAYLOAD_SHA_MISMATCH"),
            ("payload_sha256", "\u00b0" * 64, "PAYLOAD_SHA_MISMATCH"),
            ("certificate_sha256", 123, "CERT_SHA_MISMATCH"),
            ("certificate_sha256", "0" * 64, "CERT_SHA_MISMATCH"),
            ("certificate_sha256", "\u00b0" * 64, "CERT_SHA_MISMATCH"),
        ]:
            c = copy.deepcopy(cert)
            c[k] = bad_v
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_governor_certificate(c)
            self.assertEqual(cm.exception.code, code)

        for bad_cp in ("/tmp/cert.json", None, 123):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.check_certificate_file(bad_cp)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_CERT_PATH")

        for sec in ("g1_zero_chatter", "g2_glitch_and_ramp", "g3_dougong_loop"):
            c = copy.deepcopy(cert)
            c[sec]["passed"] = 1
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_governor_certificate(c)
            self.assertEqual(cm.exception.code, "BAD_PASS_FLAG")
            c2 = copy.deepcopy(cert)
            c2[sec]["passed"] = False
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.validate_governor_certificate(c2)
            self.assertEqual(cm.exception.code, "GATE_FAILED")

        with mock.patch.object(gov, "dougong_deadband_loop_q", return_value={"exact_match": False, "area_residual": "1/1", "e_diss_shoelace": "0/1"}):
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.certify_thermal_governor()
            self.assertEqual(cm.exception.code, "GATE_FAILED")

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "gov.json"
            buf_w = io.StringIO()
            with mock.patch("sys.stdout", buf_w):
                self.assertEqual(gov.main(["--write", str(p)]), 0)
            buf_s = io.StringIO()
            with mock.patch("sys.stdout", buf_s):
                self.assertEqual(gov.main([]), 0)
            self.assertEqual(p.read_text(encoding="utf-8"), buf_s.getvalue())
            buf_c = io.StringIO()
            with mock.patch("sys.stdout", buf_c):
                self.assertEqual(gov.main(["--check", str(p)]), 0)

            forged = json.loads(p.read_text(encoding="utf-8"))
            forged["g3_dougong_loop"]["coulomb"]["e_diss_shoelace"] = "999/1"
            payload = {k: forged[k] for k in forged if k not in ("payload_sha256", "certificate_sha256")}
            forged["payload_sha256"] = hashlib.sha256(gov._canonical_json_bytes(payload)).hexdigest()
            body = dict(payload)
            body["payload_sha256"] = forged["payload_sha256"]
            forged["certificate_sha256"] = hashlib.sha256(gov._canonical_json_bytes(body)).hexdigest()
            fp = Path(td) / "forged.json"
            fp.write_text(json.dumps(forged), encoding="utf-8")
            with self.assertRaises(gov.ThermalGovError) as cm:
                gov.check_certificate_file(fp)
            self.assertEqual(cm.exception.code, "LIVE_RECOMPUTE_MISMATCH")

            bad = Path(td) / "bad.json"
            bad.write_text("{corrupt", encoding="utf-8")
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                self.assertEqual(gov.main(["--check", str(bad)]), 2)
            self.assertIn("READ_OR_JSON_ERR", err.getvalue())

    # ------------------------------------------------------------------
    # 3. bin/aletheion_exoskeleton_plugins.py: B2/B5/A2 Guards & Selftest
    # ------------------------------------------------------------------
    def test_06_exoskeleton_plugins_all_guards_and_selftest(self) -> None:
        self.assertEqual(plug.check_int(plug.MAX_INT_ABS, "i"), plug.MAX_INT_ABS)
        self.assertEqual(plug.check_int(-plug.MAX_INT_ABS, "i"), -plug.MAX_INT_ABS)
        for bad in (True, 1.5, plug.MAX_INT_ABS + 1, -(plug.MAX_INT_ABS + 1)):
            with self.assertRaises(plug.PluginError) as cm:
                plug.check_int(bad, "x")
            self.assertEqual(cm.exception.code, "BAD_INT")

        self.assertEqual(plug.check_pos_int(1, "p"), 1)
        self.assertEqual(plug.check_pos_int(plug.MAX_INT_ABS, "p"), plug.MAX_INT_ABS)
        for bad in (0, -1, True, plug.MAX_INT_ABS + 1):
            with self.assertRaises(plug.PluginError) as cm:
                plug.check_pos_int(bad, "p")
            self.assertEqual(cm.exception.code, "BAD_POS_INT")

        # B5: Iterative Khipu depth cap (depth 1500 no RecursionError) + cycle detection
        deep = {"id": "leaf", "value": 1, "children": []}
        for i in range(1500):
            deep = {"id": f"n{i}", "value": 1, "children": [deep]}
        with self.assertRaises(plug.PluginError) as cm:
            plug.build_khipu_tree_checksum(deep)
        self.assertEqual(cm.exception.code, "KHIPU_DEPTH_CAP")

        exact_depth = {"id": "leaf", "value": 1, "children": []}
        for i in range(3):
            exact_depth = {"id": f"d{i}", "value": 1, "children": [exact_depth]}
        self.assertEqual(plug.build_khipu_tree_checksum(exact_depth, max_depth=3, max_nodes=4)["value"], 1)
        with self.assertRaises(plug.PluginError) as cm:
            plug.build_khipu_tree_checksum(exact_depth, max_depth=2)
        self.assertEqual(cm.exception.code, "KHIPU_DEPTH_CAP")
        with self.assertRaises(plug.PluginError) as cm:
            plug.build_khipu_tree_checksum(exact_depth, max_depth=3, max_nodes=3)
        self.assertEqual(cm.exception.code, "KHIPU_NODE_CAP")

        cyc: dict = {"id": "loop", "value": 1, "children": []}
        cyc["children"].append(cyc)
        with self.assertRaises(plug.PluginError) as cm:
            plug.build_khipu_tree_checksum(cyc)
        self.assertEqual(cm.exception.code, "KHIPU_CYCLE")

        with self.assertRaises(plug.PluginError) as cm:
            plug.build_khipu_tree_checksum([])
        self.assertEqual(cm.exception.code, "BAD_KHIPU_NODE")
        for bad_id in ("", 123):
            with self.assertRaises(plug.PluginError) as cm:
                plug.build_khipu_tree_checksum({"id": bad_id, "value": 1})
            self.assertEqual(cm.exception.code, "BAD_KHIPU_ID")
        with self.assertRaises(plug.PluginError) as cm:
            plug.build_khipu_tree_checksum({"id": "r", "value": 1, "children": "bad"})
        self.assertEqual(cm.exception.code, "BAD_KHIPU_CHILDREN")
        with self.assertRaises(plug.PluginError) as cm:
            plug.build_khipu_tree_checksum({"id": "r", "value": 10, "children": [{"id": "c1", "value": 4}, {"id": "c2", "value": 5}]})
        self.assertEqual(cm.exception.code, "KHIPU_SUM_MISMATCH")

        for bad_w, code in [
            ([], "BAD_KHIPU_WITNESS"),
            ({"payload": {"g1_hierarchical_tree_sums": []}}, "BAD_KHIPU_WITNESS"),
            ({"payload": {"g1_hierarchical_tree_sums": {"archaeological_witnesses": []}}}, "BAD_KHIPU_WITNESS"),
            ({"top_cord_sums": "bad", "cluster_head_sums": []}, "BAD_KHIPU_WITNESS"),
            ({"top_cord_sums": [], "cluster_head_sums": "bad"}, "BAD_KHIPU_WITNESS"),
            ({"top_cord_sums": [], "cluster_head_sums": []}, "EMPTY_KHIPU_WITNESS"),
            ({"payload": 123}, "EMPTY_KHIPU_WITNESS"),
            ({"top_cord_sums": ["not_dict"], "cluster_head_sums": []}, "BAD_KHIPU_ENTRY"),
            ({"top_cord_sums": [{"khipu_id": 1, "top_cord_id": 2, "top_value": 0, "cluster_values": []}], "cluster_head_sums": []}, "BAD_KHIPU_ENTRY"),
            ({"top_cord_sums": [{"khipu_id": 1, "top_cord_id": 2, "top_value": 0, "cluster_values": "bad"}], "cluster_head_sums": []}, "BAD_KHIPU_ENTRY"),
            ({"top_cord_sums": [], "cluster_head_sums": ["not_dict"]}, "BAD_KHIPU_ENTRY"),
            ({"top_cord_sums": [], "cluster_head_sums": [{"khipu_id": 1, "head_cord_id": 2, "cluster_values": [1]}]}, "BAD_KHIPU_ENTRY"),
            ({"top_cord_sums": [], "cluster_head_sums": [{"khipu_id": 1, "head_cord_id": 2, "cluster_values": "bad"}]}, "BAD_KHIPU_ENTRY"),
        ]:
            with self.assertRaises(plug.PluginError) as cm:
                plug.verify_khipu_archaeological_witnesses(bad_w)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, code)

        wrapped = {"payload": {"g1_hierarchical_tree_sums": {"archaeological_witnesses": plug.DEFAULT_KHIPU_WITNESSES}}}
        kw_res = plug.verify_khipu_archaeological_witnesses(wrapped)
        self.assertEqual((kw_res["witness_count"], kw_res["forest_total_value"]), (4, 964))

        # B5: Bounded Sona grid allocation (no OverflowError / OOM)
        self.assertEqual(plug.count_sona_torus_cycles(2, 2), 2)
        self.assertEqual(plug.count_sona_torus_cycles(2, 3), 1)
        self.assertEqual(plug.count_sona_torus_cycles(1, plug.MAX_TORUS_CELLS), 1)
        with self.assertRaises(plug.PluginError) as cm:
            plug.count_sona_torus_cycles(1, plug.MAX_TORUS_CELLS + 1)
        self.assertEqual(cm.exception.code, "GRID_TOO_LARGE")
        with self.assertRaises(plug.PluginError) as cm:
            plug.count_sona_torus_cycles(10**10, 10**10)
        self.assertEqual(cm.exception.code, "GRID_TOO_LARGE")
        with self.assertRaises(plug.PluginError) as cm:
            plug.sona_eulerian_schedule(1, plug.MAX_TORUS_CELLS + 1, [])
        self.assertEqual(cm.exception.code, "GRID_TOO_LARGE")
        self.assertEqual(plug.sona_eulerian_schedule(1, plug.MAX_TORUS_CELLS, ["x"] * plug.MAX_TORUS_CELLS)["cycle_length"], plug.MAX_TORUS_CELLS)
        with self.assertRaises(plug.PluginError) as cm:
            plug.run_plugin_selftest(repo_rows=1, repo_cols=plug.MAX_TORUS_CELLS + 1)
        self.assertEqual(cm.exception.code, "GRID_TOO_LARGE")
        self.assertEqual(plug.run_plugin_selftest(repo_rows=1, repo_cols=plug.MAX_TORUS_CELLS)["sona_repo_watchdog_rotation"]["cycle_length"], plug.MAX_TORUS_CELLS)

        self.assertTrue(plug.verify_sona_grid_theorem(max_dim=64)["theorem_verified"])
        with self.assertRaises(plug.PluginError) as cm:
            plug.verify_sona_grid_theorem(max_dim=65)
        self.assertEqual(cm.exception.code, "MAX_DIM_CAP")
        with self.assertRaises(plug.PluginError) as cm:
            plug.sona_eulerian_schedule(2, 3, "abcdef")  # type: ignore[arg-type]
        self.assertEqual(cm.exception.code, "BAD_LABEL_COUNT")
        with self.assertRaises(plug.PluginError) as cm:
            plug.sona_eulerian_schedule(2, 3, ["a", "b"])
        self.assertEqual(cm.exception.code, "BAD_LABEL_COUNT")
        for bad_lbls in ([1, "b", "c", "d", "e", "f"], ["", "b", "c", "d", "e", "f"]):
            with self.assertRaises(plug.PluginError) as cm:
                plug.sona_eulerian_schedule(2, 3, bad_lbls)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_LABEL_ITEM")
        with self.assertRaises(plug.PluginError) as cm:
            plug.sona_eulerian_schedule(4, 6, [f"r{i}" for i in range(24)])
        self.assertEqual(cm.exception.code, "SONA_NON_COPRIME_FRAGMENTATION")

        # B2 + A2: Container/arity & guarded marker/start-phoneme lookup in verify_panini_sivasutra_c1p
        for bad_sv, bad_pr, code in [
            (None, plug.CANONICAL_PRATYAHARAS, "BAD_SIVASUTRAS"),
            ([], plug.CANONICAL_PRATYAHARAS, "BAD_SIVASUTRAS"),
            (plug.SIVASUTRAS, None, "BAD_PRATYAHARAS"),
            (plug.SIVASUTRAS, [], "BAD_PRATYAHARAS"),
            (["bad"], plug.CANONICAL_PRATYAHARAS, "BAD_SIVASUTRA_ENTRY"),
            ([(1, "N1")], plug.CANONICAL_PRATYAHARAS, "BAD_SIVASUTRA_ENTRY"),
            ([(1, "", ("a",))], plug.CANONICAL_PRATYAHARAS, "BAD_MARKER"),
            ([(1, 123, ("a",))], plug.CANONICAL_PRATYAHARAS, "BAD_MARKER"),
            ([(1, "N1", "a")], plug.CANONICAL_PRATYAHARAS, "BAD_PHONES"),
            ([(1, "N1", ())], plug.CANONICAL_PRATYAHARAS, "BAD_PHONES"),
            ([(1, "N1", ("",))], plug.CANONICAL_PRATYAHARAS, "BAD_PHONEME"),
            ([(1, "N1", (123,))], plug.CANONICAL_PRATYAHARAS, "BAD_PHONEME"),
            (plug.SIVASUTRAS, ["abcd"], "BAD_PRATYAHARA_ENTRY"),
            (plug.SIVASUTRAS, [("a", "b", "c")], "BAD_PRATYAHARA_ENTRY"),
            (plug.SIVASUTRAS, [("bad", "a", "NO_SUCH_MARKER", 1)], "UNKNOWN_MARKER"),
            (plug.SIVASUTRAS, [("bad", "a", ["b"], 1)], "UNKNOWN_MARKER"),
            (plug.SIVASUTRAS, [("bad", "MISSING_P", "N1", 1)], "MISSING_START_PHONEME"),
            (plug.SIVASUTRAS, [("bad", ["a"], "N1", 1)], "MISSING_START_PHONEME"),
        ]:
            with self.assertRaises(plug.PluginError) as cm:
                plug.verify_panini_sivasutra_c1p(sivasutras=bad_sv, pratyaharas=bad_pr)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, code)

        # B2: Panini unhashable / mixed-type spine & tag_sets guards
        for bad_sp in (["a"], "ab"):
            with self.assertRaises(plug.PluginError) as cm:
                plug.encode_panini_c1p_registry(bad_sp, {"t": ["a"]})  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_SPINE")
        for bad_item in ([{}, "b"], ["", "b"], [1, "b"]):
            with self.assertRaises(plug.PluginError) as cm:
                plug.encode_panini_c1p_registry(bad_item, {"t": ["b"]})  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_SPINE_ITEM")
        with self.assertRaises(plug.PluginError) as cm:
            plug.encode_panini_c1p_registry(["a", "a"], {"t": ["a"]})
        self.assertEqual(cm.exception.code, "DUP_SPINE")
        for bad_ts in (["a"], {}):
            with self.assertRaises(plug.PluginError) as cm:
                plug.encode_panini_c1p_registry(["a", "b"], bad_ts)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_TAG_SETS")
        for bad_tag_dict in ({"": ["a"]}, {1: ["a"], "b": ["a"]}):
            with self.assertRaises(plug.PluginError) as cm:
                plug.encode_panini_c1p_registry(["a", "b"], bad_tag_dict)  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "BAD_TAG_NAME")
        for bad_m in ([], "a"):
            with self.assertRaises(plug.PluginError) as cm:
                plug.encode_panini_c1p_registry(["a", "b"], {"t": bad_m})  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "EMPTY_TAG_SET")
        for bad_member in (["z"], [{}], [123]):
            with self.assertRaises(plug.PluginError) as cm:
                plug.encode_panini_c1p_registry(["a", "b"], {"t": bad_member})  # type: ignore[arg-type]
            self.assertEqual(cm.exception.code, "UNKNOWN_SPINE_ITEM")

        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            self.assertEqual(plug.main([]), 0)
        res = json.loads(buf.getvalue())
        self.assertTrue(res["all_passed"])
        self.assertEqual(res["sona_576_grid_theorem"]["grids_checked"], 576)
        self.assertEqual(res["sona_576_grid_theorem"]["coprime_monolinear_count"], 359)
        self.assertEqual(res["sona_repo_watchdog_rotation"]["cycle_length"], 141)
        self.assertEqual(res["panini_14_sivasutra_c1p"]["c1p_exact_count"], 43)
        self.assertEqual(res["panini_14_sivasutra_c1p"]["tucker_c3_valid_single_copy_permutations"], 0)
        self.assertEqual(res["panini_14_sivasutra_c1p"]["descriptor_compression_ratio_q"], "21/5")
        self.assertEqual(res["panini_14_sivasutra_c1p"]["total_compression_ratio_q"], "21/8")

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            kp = tdp / "khipu.json"
            kp.write_text(json.dumps(wrapped), encoding="utf-8")
            buf_k = io.StringIO()
            with mock.patch("sys.stdout", buf_k):
                self.assertEqual(plug.main(["--khipu-cert", str(kp)]), 0)
            self.assertEqual(json.loads(buf_k.getvalue())["khipu_archaeological_checksum"]["witness_count"], 4)

            for bad_path in (Path("a\x00b"), Path("../secret.json")):
                with self.assertRaises(plug.PluginError) as cm:
                    plug._load_json(bad_path)
                self.assertEqual(cm.exception.code, "UNSAFE_PATH")

            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                self.assertEqual(plug.main(["--khipu-cert", str(tdp / "missing.json")]), 2)
            self.assertIn("READ_OR_JSON_ERR", err.getvalue())

            err_big = io.StringIO()
            with mock.patch("sys.stderr", err_big):
                self.assertEqual(plug.main(["--repo-rows", "1000000", "--repo-cols", "1"]), 2)
            self.assertIn("GRID_TOO_LARGE", err_big.getvalue())

    # ------------------------------------------------------------------
    # 4. Issue #16: Full In-Repo 89-Adversarial / 60-Benign Corpora & Path Guards
    # ------------------------------------------------------------------
    def test_07_in_repo_89_adversarial_60_benign_and_path_guards(self) -> None:
        self.assertEqual(len(ADVERSARIAL_ENERGY_CASES), 89)
        self.assertEqual(len(BENIGN_TELEMETRY_CONTROLS), 60)

        for idx, (payload, expected_code) in enumerate(ADVERSARIAL_ENERGY_CASES):
            with self.assertRaises(hud.HypersphericHudError, msg=f"HUD failed to reject case #{idx}: {payload!r}") as cm_h:
                hud.validate_no_floats_or_energy_claims(payload)
            self.assertEqual(cm_h.exception.code, expected_code, msg=f"HUD code mismatch on #{idx}: {payload!r}")

            with self.assertRaises(gov.ThermalGovError, msg=f"Gov failed to reject case #{idx}: {payload!r}") as cm_g:
                gov.validate_json_tree_no_floats(payload)
            self.assertEqual(cm_g.exception.code, expected_code, msg=f"Gov code mismatch on #{idx}: {payload!r}")

        for idx, control in enumerate(BENIGN_TELEMETRY_CONTROLS):
            hud.validate_no_floats_or_energy_claims(control)
            gov.validate_json_tree_no_floats(control)

        # Linear-time ReDoS guard: 4,000-char comma/dot/digit strings stay strictly < 150 ms
        for redos_probe in ("1" + "," * 4000, "1" + "." * 4000, "1" * 4000):
            t0 = time.perf_counter()
            hud.validate_no_floats_or_energy_claims({"note": redos_probe})
            gov.validate_json_tree_no_floats({"note": redos_probe})
            self.assertLess(time.perf_counter() - t0, 0.25, "ReDoS latency budget exceeded")

        # Policy string length cap boundary (exact 4096 passes, 4097 fails)
        exact_cap = "a" * gov.MAX_POLICY_TEXT_LEN
        over_cap = "a" * (gov.MAX_POLICY_TEXT_LEN + 1)
        hud.validate_no_floats_or_energy_claims({"note": exact_cap})
        gov.validate_json_tree_no_floats({"note": exact_cap})
        with self.assertRaises(hud.HypersphericHudError) as cm_hl:
            hud.validate_no_floats_or_energy_claims({"note": over_cap})
        self.assertEqual(cm_hl.exception.code, "POLICY_TEXT_TOO_LONG")
        with self.assertRaises(gov.ThermalGovError) as cm_gl:
            gov.validate_json_tree_no_floats({"note": over_cap})
        self.assertEqual(cm_gl.exception.code, "POLICY_TEXT_TOO_LONG")

        # Non-Path type checks across ALL 3 modules
        with self.assertRaises(gov.ThermalGovError) as cm_gt:
            gov._check_safe_path("/tmp/x", "gov")  # type: ignore[arg-type]
        self.assertEqual(cm_gt.exception.code, "BAD_CERT_PATH")
        with self.assertRaises(hud.HypersphericHudError) as cm_ht:
            hud._check_safe_path("/tmp/x", "hud")  # type: ignore[arg-type]
        self.assertEqual(cm_ht.exception.code, "UNSAFE_PATH")
        with self.assertRaises(plug.PluginError) as cm_pt:
            plug._check_safe_path("/tmp/x", "plug")  # type: ignore[arg-type]
        self.assertEqual(cm_pt.exception.code, "UNSAFE_PATH")

        # Forbidden system paths, root, leading '//', NUL, and '..' traversal refused across ALL 3 modules
        forbidden_paths = (
            Path("a\x00b"),
            Path("../escape.json"),
            Path("/"),
            Path("//"),
            Path("/etc"),
            Path("/etc/passwd"),
            Path("//etc/passwd"),
            Path("///etc/passwd"),
            Path("/proc/self/environ"),
            Path("/sys/class/thermal/thermal_zone0/temp"),
            Path("/dev/null"),
            Path("/boot/vmlinuz"),
            Path("/usr/bin/env"),
            Path("/bin/sh"),
            Path("/sbin/init"),
            Path("/lib/libc.so.6"),
            Path("/lib64/ld-linux-x86-64.so.2"),
            Path("/var/log/syslog"),
        )
        for bad_p in forbidden_paths:
            with self.assertRaises(gov.ThermalGovError) as cm_g:
                gov._check_safe_path(bad_p, "gov")
            self.assertEqual(cm_g.exception.code, "UNSAFE_PATH")
            with self.assertRaises(hud.HypersphericHudError) as cm_h:
                hud._check_safe_path(bad_p, "hud")
            self.assertEqual(cm_h.exception.code, "UNSAFE_PATH")
            with self.assertRaises(plug.PluginError) as cm_p:
                plug._check_safe_path(bad_p, "plug")
            self.assertEqual(cm_p.exception.code, "UNSAFE_PATH")

        # Direct _is_forbidden_system_path checks for leading '//' normalization, /dev/shm allowlist, and prefix boundary
        for p_norm in ("//etc/passwd", "///etc", "//", "/dev/shm", "/dev/null"):
            self.assertTrue(gov._is_forbidden_system_path(p_norm))
            self.assertTrue(hud._is_forbidden_system_path(p_norm))
            self.assertTrue(plug._is_forbidden_system_path(p_norm))
        for p_ok in ("/etcetera/ok.json", "/dev/shm/aletheia_slot/ok.json"):
            self.assertFalse(gov._is_forbidden_system_path(p_ok))
            self.assertFalse(hud._is_forbidden_system_path(p_ok))
            self.assertFalse(plug._is_forbidden_system_path(p_ok))

        # Surrogate path & unreadable CWD OSError -> UNSAFE_PATH (never raw UnicodeEncodeError/OSError)
        surrogate_p = Path("/tmp/bad\udcffname.json")
        with self.assertRaises(gov.ThermalGovError) as cm_gs:
            gov._check_safe_path(surrogate_p, "gov")
        self.assertEqual(cm_gs.exception.code, "UNSAFE_PATH")
        with self.assertRaises(hud.HypersphericHudError) as cm_hs:
            hud._check_safe_path(surrogate_p, "hud")
        self.assertEqual(cm_hs.exception.code, "UNSAFE_PATH")
        with self.assertRaises(plug.PluginError) as cm_ps:
            plug._check_safe_path(surrogate_p, "plug")
        self.assertEqual(cm_ps.exception.code, "UNSAFE_PATH")

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            real_dir = tdp / "real"
            real_dir.mkdir()
            real_file = real_dir / "ok.json"
            real_file.write_text(
                json.dumps(
                    {
                        "index_sha256": "a" * 64,
                        "node_count": 1,
                        "total_cross_org_edges": 0,
                        "total_historical_edges": 0,
                        "operator_taxonomy_count": 1,
                        "obstruction_taxonomy_count": 1,
                        "org_counts": {"org_a": 1},
                        "cross_org_bridge_matrix": {},
                    }
                ),
                encoding="utf-8",
            )

            # Missing file & non-UTF-8 file in governor check_certificate_file -> READ_OR_JSON_ERR
            with self.assertRaises(gov.ThermalGovError) as cm_gm:
                gov.check_certificate_file(tdp / "missing_gov.json")
            self.assertEqual(cm_gm.exception.code, "READ_OR_JSON_ERR")
            bad_utf8 = tdp / "bad_utf8.json"
            bad_utf8.write_bytes(b"\xff\xfe\x00notutf8")
            with self.assertRaises(gov.ThermalGovError) as cm_gu:
                gov.check_certificate_file(bad_utf8)
            self.assertEqual(cm_gu.exception.code, "READ_OR_JSON_ERR")

            # NUL, '..', and leading '//' anchored inside clean temp dir (independent of system prefixes)
            for bad_rel in (
                Path(f"{tdp}/a\x00b"),
                tdp / "real" / ".." / "escape.json",
                Path(f"/{tdp}/real/ok.json"),
            ):
                with self.assertRaises(gov.ThermalGovError) as cm_g:
                    gov._check_safe_path(bad_rel, "gov")
                self.assertEqual(cm_g.exception.code, "UNSAFE_PATH")
                with self.assertRaises(hud.HypersphericHudError) as cm_h:
                    hud._check_safe_path(bad_rel, "hud")
                self.assertEqual(cm_h.exception.code, "UNSAFE_PATH")
                with self.assertRaises(plug.PluginError) as cm_p:
                    plug._check_safe_path(bad_rel, "plug")
                self.assertEqual(cm_p.exception.code, "UNSAFE_PATH")

            # Leaf symlinks and system-targeting symlink parents refused; benign symlink parent resolves cleanly
            sym_file = tdp / "sym_file.json"
            sym_file.symlink_to(real_file)
            dangling_sym = tdp / "dangling.json"
            dangling_sym.symlink_to(tdp / "nonexistent.json")
            sym_dir = tdp / "sym_dir"
            sym_dir.symlink_to(real_dir)
            via_sym_parent = sym_dir / "ok.json"
            sym_etc = tdp / "sym_etc"
            sym_etc.symlink_to(Path("/etc"))
            via_sym_etc = sym_etc / "passwd"

            # Benign symlinked parent (e.g. macOS /tmp -> /private/tmp) resolves to real_dir/ok.json
            expected_resolved = Path(os.path.realpath(str(real_dir))) / "ok.json"
            self.assertEqual(gov._check_safe_path(via_sym_parent, "gov"), expected_resolved)
            self.assertEqual(hud._check_safe_path(via_sym_parent, "hud"), expected_resolved)
            self.assertEqual(plug._check_safe_path(via_sym_parent, "plug"), expected_resolved)

            for bad_sym in (sym_file, dangling_sym, via_sym_etc):
                with self.assertRaises(gov.ThermalGovError) as cm_g:
                    gov._check_safe_path(bad_sym, "write")
                self.assertEqual(cm_g.exception.code, "UNSAFE_PATH")
                with self.assertRaises(hud.HypersphericHudError) as cm_h:
                    hud._check_safe_path(bad_sym, "web_index")
                self.assertEqual(cm_h.exception.code, "UNSAFE_PATH")
                with self.assertRaises(plug.PluginError) as cm_p:
                    plug._check_safe_path(bad_sym, "khipu_cert")
                self.assertEqual(cm_p.exception.code, "UNSAFE_PATH")

            # Bounded input size cap exact boundary (<= passes, > fails) across ALL 3 modules
            f_len = len(real_file.read_bytes())
            with mock.patch.object(gov, "MAX_INPUT_BYTES", f_len):
                self.assertEqual(len(gov._read_text_safe(real_file, "gov")), f_len)
            with mock.patch.object(gov, "MAX_INPUT_BYTES", f_len - 1):
                with self.assertRaises(gov.ThermalGovError) as cm_gb:
                    gov._read_text_safe(real_file, "gov")
                self.assertEqual(cm_gb.exception.code, "READ_OR_JSON_ERR")
            with mock.patch.object(hud, "MAX_INPUT_BYTES", f_len):
                self.assertEqual(len(hud._read_text_safe(real_file, "hud", "READ_OR_JSON_ERR")), f_len)
            with mock.patch.object(hud, "MAX_INPUT_BYTES", f_len - 1):
                with self.assertRaises(hud.HypersphericHudError) as cm_hb:
                    hud._read_text_safe(real_file, "hud", "READ_OR_JSON_ERR")
                self.assertEqual(cm_hb.exception.code, "READ_OR_JSON_ERR")
            padded_json = tdp / "padded.json"
            padded_json.write_text("{}  ", encoding="utf-8")
            with mock.patch.object(plug, "MAX_INPUT_BYTES", 4):
                self.assertEqual(plug._load_json(padded_json), {})
            with mock.patch.object(plug, "MAX_INPUT_BYTES", 2):
                with self.assertRaises(plug.PluginError) as cm_pb:
                    plug._load_json(padded_json)
                self.assertEqual(cm_pb.exception.code, "READ_OR_JSON_ERR")

            # Directory (non-regular S_ISREG refusal) on read, write, rag_db, and plugins
            with self.assertRaises(gov.ThermalGovError) as cm_gr:
                gov.check_certificate_file(real_dir)
            self.assertEqual(cm_gr.exception.code, "UNSAFE_PATH")
            with self.assertRaises(hud.HypersphericHudError) as cm_hr:
                hud._load_json_file(real_dir, "web_index")
            self.assertEqual(cm_hr.exception.code, "UNSAFE_PATH")
            with self.assertRaises(hud.HypersphericHudError) as cm_hd:
                hud.inspect_rag_sqlite_hook(real_dir)
            self.assertEqual(cm_hd.exception.code, "UNSAFE_PATH")
            with self.assertRaises(plug.PluginError) as cm_pr:
                plug._load_json(real_dir)
            self.assertEqual(cm_pr.exception.code, "UNSAFE_PATH")

            # Live non-blocking FIFO refusal across ALL 3 modules (must NOT deadlock)
            fifo_path = tdp / "fifo_live"
            os.mkfifo(fifo_path)
            try:
                with self.assertRaises(gov.ThermalGovError) as cm_gf:
                    gov._read_text_safe(fifo_path, "lbl")
                self.assertEqual(cm_gf.exception.code, "UNSAFE_PATH")
                with self.assertRaises(hud.HypersphericHudError) as cm_hf:
                    hud._read_text_safe(fifo_path, "lbl", "READ_OR_JSON_ERR")
                self.assertEqual(cm_hf.exception.code, "UNSAFE_PATH")
                with self.assertRaises(hud.HypersphericHudError) as cm_hrf:
                    hud.inspect_rag_sqlite_hook(fifo_path)
                self.assertEqual(cm_hrf.exception.code, "UNSAFE_PATH")
                with self.assertRaises(plug.PluginError) as cm_pf:
                    plug._load_json(fifo_path)
                self.assertEqual(cm_pf.exception.code, "UNSAFE_PATH")
                # Write target FIFO refused before touching or blocking
                with self.assertRaises(gov.ThermalGovError) as cm_gwf:
                    gov._write_text_safe(fifo_path, "{}")
                self.assertEqual(cm_gwf.exception.code, "UNSAFE_PATH")
            finally:
                fifo_path.unlink()

            # Governor --write missing parent, hardlink refusal, atomic overwrite, short-write cleanup, and OSError
            with self.assertRaises(gov.ThermalGovError) as cm_mp:
                gov._write_text_safe(tdp / "no_such_dir" / "out.json", "{}")
            self.assertEqual(cm_mp.exception.code, "BAD_WRITE_PARENT")
            preserve_target = tdp / "preserve_target.json"
            preserve_target.write_text("LONG_ORIGINAL_CONTENT_MUST_SURVIVE", encoding="utf-8")
            hardlink_alias = tdp / "hardlink_alias.json"
            os.link(preserve_target, hardlink_alias)
            try:
                with self.assertRaises(gov.ThermalGovError) as cm_hlw:
                    gov._write_text_safe(preserve_target, "{}")
                self.assertEqual(cm_hlw.exception.code, "UNSAFE_PATH")
                self.assertEqual(preserve_target.read_text(encoding="utf-8"), "LONG_ORIGINAL_CONTENT_MUST_SURVIVE")
            finally:
                hardlink_alias.unlink()
            # Atomic overwrite replaces cleanly with shorter content and leaves zero stray .tmp files
            gov._write_text_safe(preserve_target, "{}")
            self.assertEqual(preserve_target.read_text(encoding="utf-8"), "{}")
            self.assertEqual(list(tdp.glob("*.tmp")), [])
            # Short write (0 bytes) raises WRITE_ERR and cleans up .tmp
            with mock.patch.object(gov.os, "write", return_value=0):
                with self.assertRaises(gov.ThermalGovError) as cm_sw:
                    gov._write_text_safe(preserve_target, "fail")
                self.assertEqual(cm_sw.exception.code, "WRITE_ERR")
            self.assertEqual(list(tdp.glob("*.tmp")), [])
            self.assertEqual(preserve_target.read_text(encoding="utf-8"), "{}")
            with mock.patch.object(gov.os, "open", side_effect=OSError("permission denied")):
                with self.assertRaises(gov.ThermalGovError) as cm_we:
                    gov._write_text_safe(tdp / "blocked.json", "{}")
                self.assertEqual(cm_we.exception.code, "WRITE_ERR")

            # HUD inspect_rag_sqlite_hook in-memory deserialize(): URI-named dummy file NEVER creates 'x'
            uri_dummy = tdp / "x?mode=rwc#"
            uri_dummy.write_bytes(b"not a db")
            with self.assertRaises(hud.HypersphericHudError) as cm_uri:
                hud.inspect_rag_sqlite_hook(uri_dummy)
            self.assertEqual(cm_uri.exception.code, "BAD_RAG_SQLITE")
            self.assertFalse((tdp / "x").exists(), "SQLite deserialize must never create side-effect file 'x'")

            # HUD inspect_rag_sqlite_hook bounded size cap (<= passes, > fails) & OSError -> BAD_RAG_SQLITE
            valid_rag = tdp / "valid_rag.sqlite"
            c_vr = sqlite3.connect(valid_rag)
            c_vr.execute("CREATE TABLE nodes (id TEXT)")
            c_vr.commit()
            c_vr.close()
            rag_len = len(valid_rag.read_bytes())
            with mock.patch.object(hud, "MAX_RAG_DB_BYTES", rag_len):
                self.assertEqual(hud.inspect_rag_sqlite_hook(valid_rag)["status"], "wired")
            with mock.patch.object(hud, "MAX_RAG_DB_BYTES", rag_len - 1):
                with self.assertRaises(hud.HypersphericHudError) as cm_rb:
                    hud.inspect_rag_sqlite_hook(valid_rag)
                self.assertEqual(cm_rb.exception.code, "BAD_RAG_SQLITE")
            with mock.patch.object(hud.os, "open", side_effect=OSError("eloop")):
                with self.assertRaises(hud.HypersphericHudError) as cm_re:
                    hud.inspect_rag_sqlite_hook(valid_rag)
                self.assertEqual(cm_re.exception.code, "BAD_RAG_SQLITE")

            # End-to-end CLI exit code 2 on unsafe --write, --check, --web-index, --rag-db, --khipu-cert
            for cli_fn, cli_argv in (
                (gov.main, ["--write", "../escape.json"]),
                (gov.main, ["--write", "/etc/evil.json"]),
                (gov.main, ["--write", str(sym_file)]),
                (gov.main, ["--check", "/etc/passwd"]),
                (gov.main, ["--check", str(sym_file)]),
                (hud.main, ["--once", "--web-index", "/etc/passwd"]),
                (hud.main, ["--once", "--web-index", str(sym_file)]),
                (hud.main, ["--once", "--web-index", str(real_file), "--rag-db", "/etc/passwd"]),
                (hud.main, ["--once", "--web-index", str(real_file), "--rag-db", str(dangling_sym)]),
                (plug.main, ["--khipu-cert", "/etc/passwd"]),
                (plug.main, ["--khipu-cert", str(sym_file)]),
            ):
                err_b = io.StringIO()
                with mock.patch("sys.stderr", err_b):
                    self.assertEqual(cli_fn(cli_argv), 2, msg=f"CLI failed to refuse {cli_argv!r}")
                self.assertIn("UNSAFE_PATH", err_b.getvalue(), msg=f"Missing UNSAFE_PATH for {cli_argv!r}")

            # Strict JSON refusal (malformed syntax, NaN, Infinity, -Infinity, float literal, duplicate keys, int digits > 64, depth > 64)
            self.assertEqual(hud.MAX_JSON_DEPTH, 32)
            self.assertEqual(gov.MAX_JSON_DEPTH, 32)
            int_64_pos = "1" * 64
            int_64_neg = "-" + "1" * 64
            int_65 = "1" * 65
            int_4400 = "9" * 4400
            depth_64_list = "[" * 64 + "1" + "]" * 64
            depth_65_list = "[" * 65 + "1" + "]" * 65
            depth_65_dict = '{"a":' * 65 + "1" + "}" * 65
            depth_200_list = "[" * 200 + "1" + "]" * 200
            depth_2000_list = "[" * 2000 + "1" + "]" * 2000

            # Exact 64-digit signed/unsigned int and depth-64 list pass across all 3 modules
            for raw_ok_edge in (f'{{"p": {int_64_pos}, "n": {int_64_neg}}}', depth_64_list):
                self.assertIsNotNone(plug._loads_strict_json(raw_ok_edge, "p"))
                self.assertIsNotNone(hud._loads_strict_json(raw_ok_edge, "h"))
                self.assertIsNotNone(gov._loads_strict_json(raw_ok_edge, "g"))

            prev_int_limit = sys.get_int_max_str_digits()
            sys.set_int_max_str_digits(0)
            try:
                for raw_bad, expected_code in (
                    ("{broken", "READ_OR_JSON_ERR"),
                    ('{"x": NaN}', "NON_FINITE_JSON"),
                    ('{"x": Infinity}', "NON_FINITE_JSON"),
                    ('{"x": -Infinity}', "NON_FINITE_JSON"),
                    ('{"x": 1.5}', "FLOAT_FORBIDDEN"),
                    ('{"x": 1, "x": 2}', "DUPLICATE_JSON_KEY"),
                    (f'{{"x": {int_65}}}', "INT_TOO_LONG"),
                    (f'{{"x": -{int_65}}}', "INT_TOO_LONG"),
                    (f'{{"x": {int_4400}}}', "INT_TOO_LONG"),
                    (depth_65_list, "JSON_DEPTH"),
                    (depth_65_dict, "JSON_DEPTH"),
                    (depth_200_list, "JSON_DEPTH"),
                    (depth_2000_list, "JSON_DEPTH"),
                ):
                    bad_jf = tdp / "strict_bad.json"
                    bad_jf.write_text(raw_bad, encoding="utf-8")
                    with self.assertRaises(plug.PluginError) as cm_p:
                        plug._load_json(bad_jf)
                    self.assertEqual(cm_p.exception.code, expected_code)
                    with self.assertRaises(hud.HypersphericHudError) as cm_h:
                        hud._load_json_file(bad_jf, "web_index")
                    self.assertEqual(cm_h.exception.code, expected_code)
                    with self.assertRaises(hud.HypersphericHudError) as cm_hb:
                        hud.summarize_board_and_members([raw_bad])
                    self.assertEqual(
                        cm_hb.exception.code,
                        "BAD_BOARD_JSONL" if expected_code == "READ_OR_JSON_ERR" else expected_code,
                    )
                    with self.assertRaises(gov.ThermalGovError) as cm_g:
                        gov.check_certificate_file(bad_jf)
                    self.assertEqual(cm_g.exception.code, expected_code)
                    with self.assertRaises(gov.ThermalGovError) as cm_g2:
                        gov._loads_strict_json(raw_bad, "g")
                    self.assertEqual(cm_g2.exception.code, expected_code)
                    with self.assertRaises(hud.HypersphericHudError) as cm_h2:
                        hud._loads_strict_json(raw_bad, "h")
                    self.assertEqual(cm_h2.exception.code, expected_code)
                    with self.assertRaises(plug.PluginError) as cm_p2:
                        plug._loads_strict_json(raw_bad, "p")
                    self.assertEqual(cm_p2.exception.code, expected_code)
            finally:
                sys.set_int_max_str_digits(prev_int_limit)

            # Py3.11 RecursionError parity: json.loads RecursionError maps deterministically to JSON_DEPTH
            with mock.patch("json.loads", side_effect=RecursionError("maximum recursion depth exceeded")):
                with self.assertRaises(plug.PluginError) as cm_pr:
                    plug._loads_strict_json("{}", "p")
                self.assertEqual(cm_pr.exception.code, "JSON_DEPTH")
                with self.assertRaises(hud.HypersphericHudError) as cm_hr:
                    hud._loads_strict_json("{}", "h")
                self.assertEqual(cm_hr.exception.code, "JSON_DEPTH")
                with self.assertRaises(hud.HypersphericHudError) as cm_hbr:
                    hud.summarize_board_and_members(["{}"])
                self.assertEqual(cm_hbr.exception.code, "JSON_DEPTH")
                with self.assertRaises(gov.ThermalGovError) as cm_gr:
                    gov._loads_strict_json("{}", "g")
                self.assertEqual(cm_gr.exception.code, "JSON_DEPTH")

            # Valid strict JSON preserves exact key-value pairs across ALL 3 modules
            valid_kv = '{"a": 1, "b": "ok"}'
            self.assertEqual(plug._loads_strict_json(valid_kv, "p"), {"a": 1, "b": "ok"})
            self.assertEqual(hud._loads_strict_json(valid_kv, "h"), {"a": 1, "b": "ok"})
            self.assertEqual(gov._loads_strict_json(valid_kv, "g"), {"a": 1, "b": "ok"})

    # ------------------------------------------------------------------
    # 5. bin/restore-and-verify.sh Pre-Restore Guards & docs/index.html CSP/Scope
    # ------------------------------------------------------------------
    def test_08_restore_and_verify_pre_restore_guards_and_docs_csp(self) -> None:
        restore_sh = BIN_DIR / "restore-and-verify.sh"
        verifier_mod = _load_hyphen_module("verify_epistemic_integrity", BIN_DIR / "verify_epistemic_integrity.py")
        cid = "00000000-0000-4000-8000-000000000001"
        wcid = "00000000-0000-4000-8000-000000000002"

        def _make_receipt(bundle_dir: Path, payload_dir: Path, r_cid: str) -> dict:
            m_bytes = (bundle_dir / "MIGRATION_SHA256SUMS").read_bytes()
            files = [p for p in payload_dir.rglob("*") if p.is_file() and not p.is_symlink()]
            return {
                "schema": "aletheia.migration_receipt.v1",
                "created_utc": "2026-11-26T00:00:00Z",
                "cid": r_cid,
                "mode": "full",
                "file_count": len(files),
                "total_bytes": sum(p.stat().st_size for p in files),
                "manifest_sha256": hashlib.sha256(m_bytes).hexdigest(),
            }

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            # 1. Tampered bundle MUST fail BEFORE creating or writing ANY file (including under --dry-run!)
            bad_bundle = tdp / "tampered_bundle"
            bad_payload = bad_bundle / "payload"
            (bad_payload / "gemini-antigravity-cli").mkdir(parents=True)
            (bad_payload / "expedition").mkdir(parents=True)
            (bad_payload / "expedition" / "TAMPER.txt").write_text("pwned_before_verify", encoding="utf-8")
            (bad_bundle / "MIGRATION_SHA256SUMS").write_text(
                f"{'deadbeef' * 8}  expedition/TAMPER.txt\n", encoding="utf-8"
            )
            tamper_gem = tdp / "tamper_target_gem"
            tamper_exp = tdp / "tamper_target_exp"
            for extra_flag in ([], ["--dry-run"]):
                r_tamper = subprocess.run(
                    [
                        "bash",
                        str(restore_sh),
                        "--src",
                        str(bad_bundle),
                        "--gemini-dir",
                        str(tamper_gem),
                        "--expedition-dir",
                        str(tamper_exp),
                        "--cid",
                        cid,
                        *extra_flag,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(r_tamper.returncode, 2)
                self.assertFalse((tamper_exp / "TAMPER.txt").exists(), "Tampered bundle wrote to target before verification!")
                self.assertFalse(tamper_exp.exists(), "Target expedition dir created before pre-restore verification!")
                self.assertFalse(tamper_gem.exists(), "Target gemini dir created before pre-restore verification!")

            # 2. Build a valid sealed bundle matching freeze-for-migration.sh receipt schema
            good_bundle = tdp / "good_bundle"
            good_payload = good_bundle / "payload"
            good_payload.mkdir(parents=True)
            m_src, _, _, _ = verifier_mod._build_fixture(good_payload, cid, wcid)
            (good_bundle / "MIGRATION_SHA256SUMS").write_text(m_src.read_text(encoding="utf-8"), encoding="utf-8")
            m_src.unlink()
            receipt_path = good_bundle / "MIGRATION_RECEIPT.json"
            valid_receipt = _make_receipt(good_bundle, good_payload, cid)
            receipt_path.write_text(json.dumps(valid_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            # 3. Unlisted regular file AND unlisted symlink in payload/ MUST fail closed BEFORE target writes
            unlisted_file = good_payload / "expedition" / "unlisted_evil.txt"
            unlisted_file.write_text("sneaky", encoding="utf-8")
            u_gem = tdp / "unlisted_gem"
            u_exp = tdp / "unlisted_exp"
            r_unlisted = subprocess.run(
                ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(u_gem), "--expedition-dir", str(u_exp)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_unlisted.returncode, 2)
            self.assertFalse(u_exp.exists())
            unlisted_file.unlink()

            evil_sym = good_payload / "expedition" / "evil_link"
            evil_sym.symlink_to("/etc/passwd")
            r_esym = subprocess.run(
                ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(u_gem), "--expedition-dir", str(u_exp)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_esym.returncode, 2)
            self.assertFalse(u_exp.exists())
            evil_sym.unlink()

            # 4. Disallowed manifest prefix (badprefix/x.txt) fails PRE-RESTORE with ZERO target writes
            bp_dir = good_payload / "badprefix"
            bp_dir.mkdir()
            (bp_dir / "x.txt").write_text("bad", encoding="utf-8")
            orig_manifest = (good_bundle / "MIGRATION_SHA256SUMS").read_text(encoding="utf-8")
            bp_sha = hashlib.sha256(b"bad").hexdigest()
            (good_bundle / "MIGRATION_SHA256SUMS").write_text(orig_manifest + f"{bp_sha}  badprefix/x.txt\n", encoding="utf-8")
            receipt_path.write_text(json.dumps(_make_receipt(good_bundle, good_payload, cid)) + "\n", encoding="utf-8")
            bp_gem = tdp / "bp_gem"
            bp_exp = tdp / "bp_exp"
            r_bp = subprocess.run(
                ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(bp_gem), "--expedition-dir", str(bp_exp)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_bp.returncode, 2)
            self.assertFalse(bp_exp.exists())
            # Also verify verify_epistemic_integrity.py rejects badprefix cleanly in symmetric payload mode
            with self.assertRaises(verifier_mod.IntegrityError) as cm_vp:
                verifier_mod.verify_epistemic_integrity(
                    manifest_path=good_bundle / "MIGRATION_SHA256SUMS",
                    gemini_dir=good_payload / "gemini-antigravity-cli",
                    config_dir=good_payload / "gemini-config",
                    expedition_dir=good_payload / "expedition",
                    cid=cid,
                )
            self.assertEqual(cm_vp.exception.code, "MANIFEST_UNKNOWN_PREFIX")
            # Clean up badprefix probe
            (bp_dir / "x.txt").unlink()
            bp_dir.rmdir()
            (good_bundle / "MIGRATION_SHA256SUMS").write_text(orig_manifest, encoding="utf-8")
            receipt_path.write_text(json.dumps(valid_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            # 5. Paths containing ':' (rsync remote SSH spec) or leading '-' refused with RC=2
            for bad_src in ("hostX:bundle", "-evil-bundle"):
                r_bad_s = subprocess.run(
                    ["bash", str(restore_sh), "--src", bad_src, "--gemini-dir", str(u_gem), "--expedition-dir", str(u_exp), "--cid", cid],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(r_bad_s.returncode, 2, msg=f"Failed to refuse {bad_src!r}")
                self.assertNotIn("ssh:", r_bad_s.stderr.lower())

            # 6. Symlinked target dirs refused fail-closed before touching targets
            real_dir = tdp / "real_target"
            real_dir.mkdir()
            sym_exp = tdp / "sym_exp"
            sym_exp.symlink_to(real_dir)
            r_sym_exp = subprocess.run(
                ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(tdp / "sym_test_gem"), "--expedition-dir", str(sym_exp)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_sym_exp.returncode, 2)
            self.assertIn("symlink", r_sym_exp.stderr.lower())

            sym_gem = tdp / "sym_gem"
            sym_gem.symlink_to(real_dir)
            r_sym_gem = subprocess.run(
                ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(sym_gem), "--expedition-dir", str(tdp / "sym_test_exp")],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_sym_gem.returncode, 2)
            self.assertIn("symlink", r_sym_gem.stderr.lower())

            # 7. Bad or forged MIGRATION_RECEIPT.json (NaN, float, dup key, >64d int, depth>32, bad cid, wrong schema/manifest_sha256/file_count/total_bytes) & mismatched --cid refused
            saved_receipt = receipt_path.read_text(encoding="utf-8")
            deep_nest: object = 1
            for _ in range(32):
                deep_nest = [deep_nest]
            forged_cases = [
                '{"cid": "' + cid + '", "x": NaN}',
                '{"cid": "' + cid + '", "x": 1.5}',
                '{"cid": "' + cid + '", "cid": "' + cid + '"}',
                f'{{"schema": "aletheia.migration_receipt.v1", "cid": "{cid}", "file_count": {"9" * 65}}}',
                json.dumps({**valid_receipt, "deep": deep_nest}),
                '{"cid": "../evil"}',
                '{"cid": ""}',
                json.dumps({**valid_receipt, "schema": "WRONG_SCHEMA"}),
                json.dumps({**valid_receipt, "manifest_sha256": "0" * 64}),
                json.dumps({**valid_receipt, "file_count": valid_receipt["file_count"] + 1}),
                json.dumps({**valid_receipt, "total_bytes": valid_receipt["total_bytes"] + 1}),
            ]
            for bad_rec in forged_cases:
                receipt_path.write_text(bad_rec, encoding="utf-8")
                r_bad_rec = subprocess.run(
                    ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(tdp / "rec_gem"), "--expedition-dir", str(tdp / "rec_exp")],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(r_bad_rec.returncode, 2, msg=f"Bad receipt not refused: {bad_rec}")
            receipt_path.write_text(saved_receipt, encoding="utf-8")

            r_mismatch = subprocess.run(
                [
                    "bash",
                    str(restore_sh),
                    "--src",
                    str(good_bundle),
                    "--gemini-dir",
                    str(tdp / "mis_gem"),
                    "--expedition-dir",
                    str(tdp / "mis_exp"),
                    "--cid",
                    "00000000-0000-4000-8000-000000000099",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_mismatch.returncode, 2)

            # 8. --dry-run on valid bundle verifies pre-restore AND leaves targets untouched
            ok_gem = tdp / "ok_gem"
            ok_exp = tdp / "ok_exp"
            r_dry = subprocess.run(
                ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(ok_gem), "--expedition-dir", str(ok_exp), "--dry-run"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_dry.returncode, 0, msg=r_dry.stderr)
            self.assertIn("Pre-restore payload verification PASS", r_dry.stdout)
            self.assertFalse(ok_gem.exists())
            self.assertFalse(ok_exp.exists())

            # 9. Full valid restore succeeds and prunes stale presence/*.lock cleanly
            pres = ok_gem / "antigravity-cli" / "presence"
            pres.mkdir(parents=True)
            stale_lock = pres / "stale.lock"
            stale_lock.write_text("old", encoding="utf-8")
            r_ok = subprocess.run(
                ["bash", str(restore_sh), "--src", str(good_bundle), "--gemini-dir", str(ok_gem), "--expedition-dir", str(ok_exp)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r_ok.returncode, 0, msg=f"STDOUT:\n{r_ok.stdout}\nSTDERR:\n{r_ok.stderr}")
            self.assertIn("Pre-restore payload verification PASS", r_ok.stdout)
            self.assertIn("RESTORE VERIFIED PASS", r_ok.stdout)
            self.assertEqual((ok_exp / "README.md").read_text(encoding="utf-8"), "# Expedition\n")
            self.assertFalse(stale_lock.exists(), "stale presence/*.lock was not pruned!")

        # 10. docs/index.html exact zero-external-CDN CSP, static Tailwind CSS, accurate restore-and-verify.sh size, and zero energy prose
        html = (REPO_ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        expected_csp = (
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'self\'; script-src \'self\' \'unsafe-inline\'; '
            'style-src \'self\' \'unsafe-inline\'; font-src \'self\'; img-src \'self\' data:; '
            'connect-src \'none\'; object-src \'none\'; base-uri \'self\';" />'
        )
        self.assertIn(expected_csp, html)
        head_section = html.split("</head>", 1)[0]
        self.assertNotIn("fonts.googleapis.com", head_section)
        self.assertNotIn("fonts.gstatic.com", head_section)
        self.assertNotIn("cdn.tailwindcss.com", html)
        self.assertNotIn('<script src="http', html)
        self.assertNotIn('<link rel="stylesheet" href="http', html)
        self.assertIn('<style id="tailwind-static-css">', html)
        restore_kb = f"{restore_sh.stat().st_size / 1000:.1f} KB"
        self.assertIn(f"Phase 05 · {restore_kb}", html)
        self.assertIn(f"path: 'bin/restore-and-verify.sh', size: '{restore_kb}'", html)
        self.assertNotIn("4.8 KB", html)
        for forbidden_prose in (
            "every watt",
            "additional wattage",
            "OLED power guard",
            "FAN & POWER CAP",
            "Display Power Clamp",
            "Display Power Guards",
            "SmoothClamp(P_OLED, P_SM86)",
        ):
            self.assertNotIn(forbidden_prose, html)


if __name__ == "__main__":
    unittest.main()
