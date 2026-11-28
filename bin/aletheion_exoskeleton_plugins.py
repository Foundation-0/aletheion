#!/usr/bin/env python3
"""Aletheion Pure-Z/Q Exoskeleton Plugins (`bin/aletheion_exoskeleton_plugins.py`).

Three modular pure-Z/Q verification & scheduling plugins for the Aletheion workstation shell:
  1. `khipu_tree_checksum`: Inca Khipu hierarchical additive conservation + Merkle SHA-256
     checksum, verified against reproduced Open Khipu Repository (OKR) literature summation
     constants and optional external Khipu witness JSON inputs.
  2. `sona_eulerian_scheduler`: Chokwe Sona `gcd(m, n) == 1` single-cycle torus watchdog
     scheduler (verified across all 576 grids 1..24 x 1..24 and a synthetic 141-slot 3x47 cycle).
  3. `panini_c1p_registry`: Panini 14-Sivasutra 43/43 Consecutive-Ones Property (C1P)
     interval registry encoder + exact Tucker C3 double-`h` obstruction proof + generic
     C1P registry compressor.

Zero IEEE-754 float literals in AST, zero bare asserts, bounded memory & iterative depth caps,
fail-closed PluginError.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCHEMA_PLUGINS = "aletheion.exoskeleton_plugins.v1"
MAX_INT_ABS = 10**18
MAX_KHIPU_DEPTH = 64
MAX_KHIPU_NODES = 10_000
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_TORUS_CELLS = 100_000
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

# Reproduced literature summation constants from published Open Khipu Repository (OKR) records:
DEFAULT_KHIPU_WITNESSES: Dict[str, Any] = {
    "top_cord_sums": [
        {"khipu_id": 1000037, "top_cord_id": 3005715, "top_value": 76, "cluster_values": [4, 14, 7, 37, 10, 4]},
    ],
    "cluster_head_sums": [
        {"khipu_id": 1000009, "head_cord_id": 3000827, "cluster_values": [41, 23, 11, 7]},
        {"khipu_id": 1000058, "head_cord_id": 3007285, "cluster_values": [25, 4, 4, 4, 4, 4, 5]},
        {"khipu_id": 1000127, "head_cord_id": 3014113, "cluster_values": [822, 332, 245, 245]},
    ],
}

# Canonical 14 Paninian Sivasutras: (index, it-marker, ordered phonemes).
# Contains 43 linear slots across 42 distinct phonemes with 'h' duplicated at slots 9 and 42.
SIVASUTRAS: Tuple[Tuple[int, str, Tuple[str, ...]], ...] = (
    (1, "N1", ("a", "i", "u")),
    (2, "k", ("R", "L")),
    (3, "G", ("e", "o")),
    (4, "c", ("ai", "au")),
    (5, "T", ("h", "y", "v", "r")),
    (6, "N2", ("l",)),
    (7, "m", ("ny", "m", "ng", "nr", "n")),
    (8, "J", ("jh", "bh")),
    (9, "S", ("gh", "dhr", "dh")),
    (10, "z", ("j", "b", "g", "dr", "d")),
    (11, "v", ("kh", "ph", "ch", "thr", "th", "c", "tr", "t")),
    (12, "y", ("k", "p")),
    (13, "r", ("sh", "sr", "s")),
    (14, "l", ("h",)),
)

# Canonical 43 Paninian pratyaharas: (name, start_phoneme, end_marker, expected_member_count).
CANONICAL_PRATYAHARAS: Tuple[Tuple[str, str, str, int], ...] = (
    ("aN", "a", "N1", 3),
    ("ak", "a", "k", 5),
    ("ik", "i", "k", 4),
    ("uk", "u", "k", 3),
    ("eG", "e", "G", 2),
    ("ac", "a", "c", 9),
    ("ic", "i", "c", 8),
    ("ec", "e", "c", 4),
    ("aic", "ai", "c", 2),
    ("aT", "a", "T", 13),
    ("aN2", "a", "N2", 14),
    ("iN", "i", "N2", 13),
    ("yaN", "y", "N2", 4),
    ("ra", "r", "N2", 2),
    ("am", "a", "m", 19),
    ("yam", "y", "m", 9),
    ("Gam", "ng", "m", 3),
    ("yaJ", "y", "J", 11),
    ("jhaS", "jh", "S", 5),
    ("bhaS", "bh", "S", 4),
    ("az", "a", "z", 29),
    ("haz", "h", "z", 20),
    ("vaz", "v", "z", 18),
    ("jhaz", "jh", "z", 10),
    ("jaz", "j", "z", 5),
    ("baz", "b", "z", 4),
    ("chav", "ch", "v", 6),
    ("yay", "y", "y", 29),
    ("may", "m", "y", 24),
    ("jhay", "jh", "y", 20),
    ("khay", "kh", "y", 10),
    ("cay", "c", "y", 5),
    ("yar", "y", "r", 32),
    ("jhar", "jh", "r", 23),
    ("khar", "kh", "r", 13),
    ("car", "c", "r", 8),
    ("zar", "sh", "r", 3),
    ("al", "a", "l", 42),
    ("hal", "h", "l", 33),
    ("val", "v", "l", 32),
    ("ral", "r", "l", 31),
    ("jhal", "jh", "l", 24),
    ("zal", "sh", "l", 4),
)


class PluginError(ValueError):
    """Fail-closed error for Aletheion exoskeleton plugins."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"[{code}] {detail}")


def require_ok(cond: bool, code: str, detail: str) -> None:
    if not cond:
        raise PluginError(code, detail)


def check_int(val: Any, name: str) -> int:
    require_ok(type(val) is int and abs(val) <= MAX_INT_ABS, "BAD_INT", f"{name} must be bounded int")
    return val


def check_pos_int(val: Any, name: str) -> int:
    require_ok(type(val) is int and 0 < val <= MAX_INT_ABS, "BAD_POS_INT", f"{name} must be positive int")
    return val


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Plugin 1: `khipu_tree_checksum` (Iterative Bounded-Depth Tree-Sum + Merkle)
# ---------------------------------------------------------------------------


def build_khipu_tree_checksum(
    node: Any,
    max_depth: int = MAX_KHIPU_DEPTH,
    max_nodes: int = MAX_KHIPU_NODES,
) -> Dict[str, Any]:
    """Iteratively verify additive conservation `value == sum(child.value)` and Merkle SHA-256."""
    depth_cap = check_pos_int(max_depth, "max_depth")
    node_cap = check_pos_int(max_nodes, "max_nodes")
    stack: List[Tuple[Any, int, int]] = [(node, 0, 0)]
    results: Dict[int, Dict[str, Any]] = {}
    active_ids: set[int] = set()
    visited_nodes = 0

    while stack:
        cur, depth, phase = stack.pop()
        if phase == 0:
            visited_nodes += 1
            require_ok(visited_nodes <= node_cap, "KHIPU_NODE_CAP", "Khipu tree node count exceeds cap")
            require_ok(depth <= depth_cap, "KHIPU_DEPTH_CAP", "Khipu tree depth exceeds cap")
            require_ok(type(cur) is dict, "BAD_KHIPU_NODE", "Khipu node must be dict")
            oid = id(cur)
            require_ok(oid not in active_ids, "KHIPU_CYCLE", "Cyclic Khipu node reference detected")
            nid = cur.get("id")
            require_ok(type(nid) is str and len(nid) >= 1, "BAD_KHIPU_ID", "Khipu node id must be non-empty str")
            check_int(cur.get("value"), f"{nid}.value")
            children = cur.get("children", [])
            require_ok(type(children) is list, "BAD_KHIPU_CHILDREN", f"{nid}.children must be list")
            active_ids.add(oid)
            stack.append((cur, depth, 1))
            for ch in reversed(children):
                stack.append((ch, depth + 1, 0))
        else:
            oid = id(cur)
            active_ids.discard(oid)
            nid = cur["id"]
            val = cur["value"]
            children = cur.get("children", [])
            child_digests: List[str] = []
            if children:
                child_sum = 0
                for ch in children:
                    sub = results[id(ch)]
                    child_sum += sub["value"]
                    child_digests.append(sub["merkle_sha256"])
                require_ok(val == child_sum, "KHIPU_SUM_MISMATCH", f"{nid}: declared {val} != child sum {child_sum}")
            digest_payload = {"id": nid, "value": val, "children_sha256": child_digests}
            merkle = hashlib.sha256(_canonical_json_bytes(digest_payload)).hexdigest()
            results[oid] = {
                "id": nid,
                "value": val,
                "child_count": len(children),
                "merkle_sha256": merkle,
            }

    return results[id(node)]


def verify_khipu_archaeological_witnesses(witness_obj: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Verify Khipu top-cord & cluster-head summation witnesses via `build_khipu_tree_checksum`."""
    raw = DEFAULT_KHIPU_WITNESSES if witness_obj is None else witness_obj
    require_ok(type(raw) is dict, "BAD_KHIPU_WITNESS", "Witness container must be dict")
    if "payload" in raw and type(raw["payload"]) is dict:
        g1 = raw["payload"].get("g1_hierarchical_tree_sums")
        require_ok(type(g1) is dict, "BAD_KHIPU_WITNESS", "Missing g1_hierarchical_tree_sums")
        raw = g1.get("archaeological_witnesses")
        require_ok(type(raw) is dict, "BAD_KHIPU_WITNESS", "Missing archaeological_witnesses")

    top_list = raw.get("top_cord_sums", [])
    head_list = raw.get("cluster_head_sums", [])
    require_ok(type(top_list) is list and type(head_list) is list, "BAD_KHIPU_WITNESS", "Witness lists must be list")
    require_ok(len(top_list) + len(head_list) >= 1, "EMPTY_KHIPU_WITNESS", "At least one witness required")

    checked: List[Dict[str, Any]] = []
    for entry in top_list:
        require_ok(type(entry) is dict, "BAD_KHIPU_ENTRY", "top_cord entry must be dict")
        vals = entry.get("cluster_values")
        require_ok(type(vals) is list and len(vals) >= 1, "BAD_KHIPU_ENTRY", "cluster_values must be non-empty list")
        tree = {
            "id": f"khipu_{entry.get('khipu_id')}_top_{entry.get('top_cord_id')}",
            "value": entry.get("top_value"),
            "children": [{"id": f"c_{i}", "value": v} for i, v in enumerate(vals)],
        }
        checked.append(build_khipu_tree_checksum(tree))

    for entry in head_list:
        require_ok(type(entry) is dict, "BAD_KHIPU_ENTRY", "cluster_head entry must be dict")
        vals = entry.get("cluster_values")
        require_ok(type(vals) is list and len(vals) >= 2, "BAD_KHIPU_ENTRY", "cluster_head values must have len >= 2")
        tree = {
            "id": f"khipu_{entry.get('khipu_id')}_head_{entry.get('head_cord_id')}",
            "value": vals[0],
            "children": [{"id": f"c_{i}", "value": v} for i, v in enumerate(vals[1:])],
        }
        checked.append(build_khipu_tree_checksum(tree))

    root_tree = {
        "id": "okr_verified_forest",
        "value": sum(c["value"] for c in checked),
        "children": [{"id": c["id"], "value": c["value"]} for c in checked],
    }
    forest = build_khipu_tree_checksum(root_tree)
    return {
        "witness_count": len(checked),
        "top_cord_count": len(top_list),
        "cluster_head_count": len(head_list),
        "forest_total_value": forest["value"],
        "forest_merkle_sha256": forest["merkle_sha256"],
    }


# ---------------------------------------------------------------------------
# Plugin 2: `sona_eulerian_scheduler` (Bounded Chokwe Sona Torus Scheduler)
# ---------------------------------------------------------------------------


def count_sona_torus_cycles(rows_m: Any, cols_n: Any) -> int:
    """Count exact closed diagonal orbits of `(r, c) -> ((r + 1) % m, (c + 1) % n)` on `(Z/mZ) x (Z/nZ)`."""
    m = check_pos_int(rows_m, "rows_m")
    n = check_pos_int(cols_n, "cols_n")
    require_ok(m * n <= MAX_TORUS_CELLS, "GRID_TOO_LARGE", f"Grid m*n={m * n} exceeds cap {MAX_TORUS_CELLS}")
    visited = bytearray(m * n)
    cycles = 0
    for start in range(m * n):
        if visited[start]:
            continue
        cycles += 1
        r, c = divmod(start, n)
        while not visited[r * n + c]:
            visited[r * n + c] = 1
            r = (r + 1) % m
            c = (c + 1) % n
    return cycles


def verify_sona_grid_theorem(max_dim: int = 24) -> Dict[str, Any]:
    """Verify `count_sona_torus_cycles(m, n) == gcd(m, n)` across all `max_dim^2` grids."""
    dmax = check_pos_int(max_dim, "max_dim")
    require_ok(dmax <= 64, "MAX_DIM_CAP", "max_dim must be <= 64")
    exact_matches = 0
    coprime_count = 0
    for m in range(1, dmax + 1):
        for n in range(1, dmax + 1):
            g = math.gcd(m, n)
            cyc = count_sona_torus_cycles(m, n)
            if cyc == g:
                exact_matches += 1
            if g == 1:
                coprime_count += 1
    total = dmax * dmax
    return {
        "max_dim": dmax,
        "grids_checked": total,
        "exact_gcd_loop_matches": exact_matches,
        "coprime_monolinear_count": coprime_count,
        "theorem_verified": exact_matches == total,
    }


def sona_eulerian_schedule(rows_m: Any, cols_n: Any, labels: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Generate a single-cycle Chokwe Sona diagonal torus traversal over an `(m, n)` label grid."""
    m = check_pos_int(rows_m, "rows_m")
    n = check_pos_int(cols_n, "cols_n")
    require_ok(m * n <= MAX_TORUS_CELLS, "GRID_TOO_LARGE", f"Grid m*n={m * n} exceeds cap {MAX_TORUS_CELLS}")
    if labels is None:
        resolved_labels: Sequence[str] = [f"repo_{i:03d}" for i in range(m * n)]
    else:
        require_ok(type(labels) in (list, tuple) and len(labels) == m * n, "BAD_LABEL_COUNT", "len(labels) must equal m * n")
        for lbl in labels:
            require_ok(type(lbl) is str and len(lbl) >= 1, "BAD_LABEL_ITEM", "Each label must be non-empty str")
        resolved_labels = labels
    g = math.gcd(m, n)
    require_ok(g == 1, "SONA_NON_COPRIME_FRAGMENTATION", f"gcd({m},{n})={g} fragments schedule into {g} loops")
    order: List[str] = []
    visited: set[Tuple[int, int]] = set()
    for step in range(m * n):
        r, c = step % m, step % n
        visited.add((r, c))
        order.append(resolved_labels[r * n + c])
    return {
        "rows_m": m,
        "cols_n": n,
        "gcd": g,
        "cycle_length": len(order),
        "unique_cells_visited": len(visited),
        "single_eulerian_cycle": len(visited) == m * n,
        "schedule": order,
    }


# ---------------------------------------------------------------------------
# Plugin 3: `panini_c1p_registry` (Panini 14-Sivasutra 43/43 C1P + Tucker C3)
# ---------------------------------------------------------------------------


def verify_panini_sivasutra_c1p(
    sivasutras: Sequence[Tuple[int, str, Tuple[str, ...]]] = SIVASUTRAS,
    pratyaharas: Sequence[Tuple[str, str, str, int]] = CANONICAL_PRATYAHARAS,
) -> Dict[str, Any]:
    """Verify Paninian pratyaharas on the 14 Sivasutras + exact Tucker C3 double-`h` obstruction."""
    require_ok(type(sivasutras) in (list, tuple) and len(sivasutras) >= 1, "BAD_SIVASUTRAS", "sivasutras must be non-empty list/tuple")
    require_ok(type(pratyaharas) in (list, tuple) and len(pratyaharas) >= 1, "BAD_PRATYAHARAS", "pratyaharas must be non-empty list/tuple")
    slots: List[str] = []
    marker_end: Dict[str, int] = {}
    for entry in sivasutras:
        require_ok(type(entry) in (list, tuple) and len(entry) == 3, "BAD_SIVASUTRA_ENTRY", "Each sivasutra must be 3-tuple")
        _, marker, phones = entry
        require_ok(type(marker) is str and len(marker) >= 1, "BAD_MARKER", "it-marker must be non-empty str")
        require_ok(type(phones) in (list, tuple) and len(phones) >= 1, "BAD_PHONES", "phones must be non-empty list/tuple")
        for p in phones:
            require_ok(type(p) is str and len(p) >= 1, "BAD_PHONEME", "phoneme must be non-empty str")
            slots.append(p)
        marker_end[marker] = len(slots) - 1

    dup_h_indices = [i for i, p in enumerate(slots) if p == "h"]
    exact_count = 0
    for pr in pratyaharas:
        require_ok(type(pr) in (list, tuple) and len(pr) == 4, "BAD_PRATYAHARA_ENTRY", "Each pratyahara must be 4-tuple")
        name, start_p, end_m, exp_len = pr
        require_ok(type(end_m) is str and end_m in marker_end, "UNKNOWN_MARKER", f"Unknown it-marker {end_m} for {name}")
        end_idx = marker_end[end_m]
        start_idx = next((i for i in range(end_idx + 1) if slots[i] == start_p), None) if type(start_p) is str else None
        require_ok(start_idx is not None, "MISSING_START_PHONEME", f"Start phoneme {start_p} not found before {end_m}")
        members = frozenset(slots[start_idx : end_idx + 1])
        if len(members) == exp_len:
            exact_count += 1

    c3_sets = (frozenset({"y", "h"}), frozenset({"sh", "h"}), frozenset({"y", "sh"}))
    valid_single_perms = 0
    for perm in itertools.permutations(("y", "sh", "h")):
        ok_all = True
        for s in c3_sets:
            idxs = [perm.index(x) for x in s]
            if max(idxs) - min(idxs) + 1 != len(idxs):
                ok_all = False
                break
        if ok_all:
            valid_single_perms += 1

    dup_spine = ("h", "y", "sh", "h")
    dup_resolved = all(
        any(frozenset(dup_spine[i : j + 1]) == s for i in range(4) for j in range(i, 4))
        for s in c3_sets
    )

    n_distinct = len(set(slots))
    n_slots = len(slots)
    n_praty = len(pratyaharas)
    naive_bits = n_praty * n_distinct
    desc_bits = n_praty * 10
    total_bits = desc_bits + n_slots * (n_distinct - 1).bit_length()
    desc_ratio = Fraction(naive_bits, desc_bits)
    total_ratio = Fraction(naive_bits, total_bits)

    return {
        "sivasutra_count": len(sivasutras),
        "slot_count": n_slots,
        "distinct_phoneme_count": n_distinct,
        "duplicate_h_slot_indices": dup_h_indices,
        "pratyahara_count": n_praty,
        "c1p_exact_count": exact_count,
        "tucker_c3_valid_single_copy_permutations": valid_single_perms,
        "tucker_c3_duplicate_h_resolves": dup_resolved,
        "naive_bitset_bits": naive_bits,
        "panini_descriptor_bits": desc_bits,
        "panini_total_bits_with_table": total_bits,
        "descriptor_compression_ratio_q": f"{desc_ratio.numerator}/{desc_ratio.denominator}",
        "total_compression_ratio_q": f"{total_ratio.numerator}/{total_ratio.denominator}",
        "all_verified": all((exact_count == n_praty, valid_single_perms == 0, dup_resolved)),
    }


def encode_panini_c1p_registry(
    spine: Sequence[str],
    tag_sets: Dict[str, Sequence[str]],
) -> Dict[str, Any]:
    """Encode tag subsets as exact C1P contiguous intervals `(lo, hi)` along a unique ordered spine."""
    require_ok(type(spine) in (list, tuple) and len(spine) >= 2, "BAD_SPINE", "Spine must have len >= 2")
    for item in spine:
        require_ok(type(item) is str and len(item) >= 1, "BAD_SPINE_ITEM", "Spine items must be non-empty str")
    require_ok(len(set(spine)) == len(spine), "DUP_SPINE", "Spine entries must be unique")
    require_ok(type(tag_sets) is dict and len(tag_sets) >= 1, "BAD_TAG_SETS", "tag_sets must be non-empty dict")
    for tag in tag_sets:
        require_ok(type(tag) is str and len(tag) >= 1, "BAD_TAG_NAME", "Tag name must be non-empty str")
    pos = {name: idx for idx, name in enumerate(spine)}

    intervals: Dict[str, Tuple[int, int]] = {}
    obstructed: Dict[str, List[str]] = {}
    for tag in sorted(tag_sets):
        members = tag_sets[tag]
        require_ok(type(members) in (list, tuple) and len(members) >= 1, "EMPTY_TAG_SET", f"Tag {tag} must be non-empty")
        idxs: List[int] = []
        for item in members:
            require_ok(type(item) is str and item in pos, "UNKNOWN_SPINE_ITEM", f"Item {item!r} missing from spine")
            idxs.append(pos[item])
        uniq = sorted(set(idxs))
        lo, hi = uniq[0], uniq[-1]
        if hi - lo + 1 == len(uniq):
            intervals[tag] = (lo, hi)
        else:
            gaps = [spine[k] for k in range(lo, hi + 1) if k not in set(uniq)]
            obstructed[tag] = gaps

    n_spine = len(spine)
    n_tags = len(tag_sets)
    idx_bits = (n_spine - 1).bit_length()
    naive_bits = n_tags * n_spine
    c1p_bits = n_tags * 2 * idx_bits
    ratio = Fraction(naive_bits, c1p_bits)
    return {
        "spine_len": n_spine,
        "tag_count": n_tags,
        "c1p_admissible": len(obstructed) == 0,
        "intervals": {k: [v[0], v[1]] for k, v in intervals.items()},
        "obstructed_tags": obstructed,
        "naive_bitset_bits": naive_bits,
        "c1p_descriptor_bits": c1p_bits,
        "compression_ratio_q": f"{ratio.numerator}/{ratio.denominator}",
    }


def run_plugin_selftest(
    khipu_witnesses: Optional[Dict[str, Any]] = None,
    repo_rows: int = 3,
    repo_cols: int = 47,
) -> Dict[str, Any]:
    """Verify all 3 exoskeleton plugins deterministically over canonical witnesses & synthetic rotation."""
    khipu_res = verify_khipu_archaeological_witnesses(khipu_witnesses)
    sona_grid = verify_sona_grid_theorem(max_dim=24)
    sona_repo = sona_eulerian_schedule(repo_rows, repo_cols)
    panini_siva = verify_panini_sivasutra_c1p()
    spine = [f"item_{i}" for i in range(32)]
    panini_generic_ok = encode_panini_c1p_registry(
        spine,
        {"grp_a": spine[0:8], "grp_b": spine[4:16], "grp_c": spine[12:28]},
    )
    panini_generic_gap = encode_panini_c1p_registry(spine, {"non_c1p": [spine[0], spine[2]]})
    payload = {
        "schema": SCHEMA_PLUGINS,
        "zero_floats": True,
        "khipu_archaeological_checksum": khipu_res,
        "sona_576_grid_theorem": sona_grid,
        "sona_repo_watchdog_rotation": {k: v for k, v in sona_repo.items() if k != "schedule"},
        "panini_14_sivasutra_c1p": panini_siva,
        "panini_generic_admissible": panini_generic_ok,
        "panini_generic_obstruction": panini_generic_gap,
        "all_passed": all(
            (
                sona_grid["theorem_verified"],
                sona_repo["single_eulerian_cycle"],
                panini_siva["all_verified"],
                panini_generic_ok["c1p_admissible"],
                not panini_generic_gap["c1p_admissible"],
            )
        ),
    }
    payload["plugin_selftest_sha256"] = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return payload


def _is_forbidden_system_path(path_str: str) -> bool:
    norm = re.sub(r"^/+", "/", path_str)
    if norm == "/":
        return True
    if norm.startswith("/dev/shm/"):
        return False
    return any(norm == pfx or norm.startswith(pfx + "/") for pfx in _FORBIDDEN_SYS_PREFIXES)


def _check_safe_path(path: Path, label: str) -> Path:
    require_ok(isinstance(path, Path), "UNSAFE_PATH", f"{label} must be Path")
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
        raise PluginError("UNSAFE_PATH", f"{label} path resolution failed: {exc}") from exc
    resolved = real_parent / abs_path.name
    require_ok(not _is_forbidden_system_path(resolved.as_posix()), "UNSAFE_PATH", f"{label} targets forbidden system path")
    require_ok(not resolved.is_symlink(), "UNSAFE_PATH", f"{label} symlink target forbidden")
    return resolved


MAX_JSON_INT_DIGITS = 64
MAX_JSON_DEPTH = 64


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
        raise PluginError("NON_FINITE_JSON", f"{label}: non-finite JSON constant {tok!r} forbidden")

    def _reject_float(tok: str) -> Any:
        raise PluginError("FLOAT_FORBIDDEN", f"{label}: float literal {tok!r} forbidden")

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
    except PluginError:
        raise
    except RecursionError as exc:
        raise PluginError("JSON_DEPTH", f"{label}: JSON nesting depth exceeds recursion limit") from exc
    except ValueError as exc:
        raise PluginError("READ_OR_JSON_ERR", f"Failed loading {label} JSON: {exc}") from exc
    _check_json_depth(parsed, MAX_JSON_DEPTH, label)
    return parsed


def _load_json(path: Path) -> Any:
    safe = _check_safe_path(path, "khipu_cert")
    parent_fd = -1
    fd = -1
    try:
        parent_fd = os.open(str(safe.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fd = os.open(safe.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        st = os.fstat(fd)
        require_ok(stat.S_ISREG(st.st_mode), "UNSAFE_PATH", "khipu_cert must be a regular file")
        require_ok(st.st_size <= MAX_INPUT_BYTES, "READ_OR_JSON_ERR", "khipu_cert exceeds max size cap")
        os.set_blocking(fd, True)
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw_text = fh.read(MAX_INPUT_BYTES).decode("utf-8")
        return _loads_strict_json(raw_text, "khipu_cert")
    except PluginError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise PluginError("READ_OR_JSON_ERR", f"Failed loading khipu witness JSON: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Aletheion Pure-Z/Q Exoskeleton Plugins Selftest")
    parser.add_argument("--json", action="store_true", help="Emit canonical JSON (default)")
    parser.add_argument("--khipu-cert", type=Path, default=None, help="Optional Khipu witness JSON")
    parser.add_argument("--repo-rows", type=int, default=3, help="Coprime watchdog grid rows (default 3)")
    parser.add_argument("--repo-cols", type=int, default=47, help="Coprime watchdog grid cols (default 47 -> 141 slots)")
    args = parser.parse_args(argv)
    try:
        kw = _load_json(args.khipu_cert) if args.khipu_cert is not None else None
        res = run_plugin_selftest(khipu_witnesses=kw, repo_rows=args.repo_rows, repo_cols=args.repo_cols)
        sys.stdout.write(json.dumps(res, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except PluginError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
