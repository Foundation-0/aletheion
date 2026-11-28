#!/usr/bin/env python3
"""
Regression and mutation-hardening tests for `aletheia-shell`:
  - `bin/verify_epistemic_integrity.py` (100% refusal-site & boundary kill coverage)
  - `bin/toroid-hud.py` (100% refusal-site & boundary kill coverage)
  - `bin/freeze-for-migration.sh`, `bin/restore-and-verify.sh`, `bin/bootstrap-zenbook.sh`
    (`bash -n` syntax, `--dry-run`, and end-to-end synthetic restore + integrity cycle)

Zero external dependencies. Zero bare asserts. Zero floats. Safe across all 3 isolated modes.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = ROOT / "bin"
VERIFY_PATH = BIN_DIR / "verify_epistemic_integrity.py"
HUD_PATH = BIN_DIR / "toroid-hud.py"


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


verify_mod = _load_module("verify_epistemic_integrity_mod", VERIFY_PATH)
hud_mod = _load_module("toroid_hud_mod", HUD_PATH)


def _capture_main(mod: ModuleType, argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = mod.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestVerifyEpistemicIntegrity(unittest.TestCase):
    def test_01_self_test_and_cli_modes(self) -> None:
        rc0, out0, err0 = _capture_main(verify_mod, [])
        self.assertEqual(rc0, 0)
        self.assertEqual(err0, "")
        rc1, out1, err1 = _capture_main(verify_mod, ["--self-test"])
        self.assertEqual(rc1, 0)
        self.assertEqual(err1, "")
        self.assertEqual(out0, out1)
        data = json.loads(out1)
        self.assertEqual(data["status"], "PASS")
        self.assertIs(data["clean_verified"], True)
        self.assertEqual(
            data["fail_closed_controls"],
            {
                "tampered_sha256": "SHA256_MISMATCH",
                "corrupted_sqlite": "SQLITE_CORRUPT",
                "truncated_board": "TRUNCATED_BOARD_LINE",
                "missing_member_db": "FILE_NOT_FOUND",
                "symlinked_input": "SYMLINK_FORBIDDEN",
            },
        )

        # Missing required CLI args fail closed with rc=2 in both JSON and text modes.
        for partial in (
            ["--gemini-dir", "/tmp", "--expedition-dir", "/tmp", "--cid", "c1"],
            ["--manifest", "/tmp/m", "--expedition-dir", "/tmp", "--cid", "c1"],
            ["--manifest", "/tmp/m", "--gemini-dir", "/tmp", "--cid", "c1"],
            ["--manifest", "/tmp/m", "--gemini-dir", "/tmp", "--expedition-dir", "/tmp"],
        ):
            rc_j, out_j, _ = _capture_main(verify_mod, partial + ["--json"])
            self.assertEqual(rc_j, 2)
            self.assertEqual(json.loads(out_j)["code"], "MISSING_ARG")
            rc_t, _, err_t = _capture_main(verify_mod, partial)
            self.assertEqual(rc_t, 2)
            self.assertIn("MISSING_ARG", err_t)

    def test_02_low_level_io_json_and_manifest_guards(self) -> None:
        # Hex validation boundaries (63, 64, 65, uppercase).
        self.assertTrue(verify_mod._is_sha256_hex("0" * 64))
        self.assertFalse(verify_mod._is_sha256_hex("0" * 63))
        self.assertFalse(verify_mod._is_sha256_hex("0" * 65))
        self.assertFalse(verify_mod._is_sha256_hex("A" * 64))

        # Strict JSON checks (empty, constant, float, dup key, syntax, surrogates).
        for raw, exp_code in (
            ("   ", "EMPTY_JSON"),
            ("NaN", "JSON_CONSTANT_FORBIDDEN"),
            ("Infinity", "JSON_CONSTANT_FORBIDDEN"),
            ("1.5", "JSON_FLOAT_FORBIDDEN"),
            ('{"a":1,"a":2}', "JSON_DUPLICATE_KEY"),
            ("{bad", "JSON_SYNTAX_ERROR"),
            ('{"k":"\\ud800"}', "LONE_SURROGATE"),
            ('{"\\udfff":"v"}', "LONE_SURROGATE"),
            ('["\\ud800"]', "LONE_SURROGATE"),
        ):
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod.loads_strict_json(raw, "t")
            self.assertEqual(cm.exception.code, exp_code, raw)
        self.assertEqual(verify_mod.loads_strict_json('{"k":"\\ud7ff\\ue000"}', "t")["k"], "\ud7ff\ue000")
        self.assertEqual(verify_mod.loads_strict_json("2", "t", allow_float=True), 2)

        with tempfile.TemporaryDirectory(prefix="alsh_io_") as td:
            root = Path(td)
            # NUL path, '..', root '/', symlink ancestor, missing dir, non-regular dir, permission error.
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._split_safe_parts(Path("a\x00b"), "t")
            self.assertEqual(cm.exception.code, "NUL_PATH")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._split_safe_parts(Path("a/../b"), "t")
            self.assertEqual(cm.exception.code, "PATH_TRAVERSAL")
            rel_parts = verify_mod._split_safe_parts(Path("./sub"), "t")
            self.assertEqual(rel_parts[-1], "sub")

            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._open_regular_fd(Path("/"), "t")
            self.assertEqual(cm.exception.code, "NOT_REGULAR_FILE")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._open_regular_fd(root, "t")
            self.assertEqual(cm.exception.code, "NOT_REGULAR_FILE")

            real_dir = root / "real"
            real_dir.mkdir()
            f_ok = real_dir / "ok.txt"
            f_ok.write_bytes(b"abcd")
            sym_dir = root / "symd"
            sym_dir.symlink_to(real_dir)
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._read_text_safe(sym_dir / "ok.txt", "t")
            self.assertEqual(cm.exception.code, "SYMLINK_FORBIDDEN")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._read_text_safe(root / "no_dir" / "ok.txt", "t")
            self.assertEqual(cm.exception.code, "PATH_NOT_FOUND")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._read_text_safe(f_ok / "child", "t")
            self.assertEqual(cm.exception.code, "SYMLINK_FORBIDDEN")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._read_text_safe(real_dir / "missing.txt", "t")
            self.assertEqual(cm.exception.code, "FILE_NOT_FOUND")

            # Exact max_bytes boundary (4 passes, 3 fails) & invalid UTF-8.
            self.assertEqual(verify_mod._read_text_safe(f_ok, "t", max_bytes=4), "abcd")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._read_text_safe(f_ok, "t", max_bytes=3)
            self.assertEqual(cm.exception.code, "FILE_TOO_LARGE")
            bad_utf = real_dir / "bad.bin"
            bad_utf.write_bytes(b"\xff\xfe")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod._read_text_safe(bad_utf, "t")
            self.assertEqual(cm.exception.code, "INVALID_UTF8")

            # Unreadable file and directory -> IO_ERROR (skipped if running as root).
            if os.geteuid() != 0:
                no_read = real_dir / "noread.txt"
                no_read.write_text("x", encoding="utf-8")
                no_read.chmod(0o000)
                no_dir = root / "nodir"
                no_dir.mkdir(mode=0o000)
                try:
                    with self.assertRaises(verify_mod.IntegrityError) as cm:
                        verify_mod._open_regular_fd(no_read, "t")
                    self.assertEqual(cm.exception.code, "IO_ERROR")
                    with self.assertRaises(verify_mod.IntegrityError) as cm:
                        verify_mod._open_regular_fd(no_dir / "x", "t")
                    self.assertEqual(cm.exception.code, "IO_ERROR")
                finally:
                    no_read.chmod(0o600)
                    no_dir.chmod(0o700)

            # Manifest edge cases.
            gem = root / "gem"
            exp = root / "exp"
            gem.mkdir()
            exp.mkdir()
            (exp / "a.txt").write_text("hi\n", encoding="utf-8")
            da = hashlib.sha256(b"hi\n").hexdigest()
            m_path = root / "M"
            for content, exp_code in (
                ("\n   \n", "EMPTY_MANIFEST"),
                ("badline_without_double_space\n", "MALFORMED_MANIFEST_LINE"),
                ("zz  expedition/a.txt\n", "INVALID_MANIFEST_DIGEST"),
                (f"{da}  expedition/a.txt\n{da}  expedition/a.txt\n", "DUPLICATE_MANIFEST_ENTRY"),
                (f"{'0'*64}  /etc/passwd\n", "MANIFEST_ABS_PATH"),
                (f"{'0'*64}  expedition/../a.txt\n", "MANIFEST_TRAVERSAL"),
                (f"{'0'*64}  unknown/a.txt\n", "MANIFEST_UNKNOWN_PREFIX"),
            ):
                m_path.write_text(content, encoding="utf-8")
                with self.assertRaises(verify_mod.IntegrityError) as cm:
                    verify_mod.verify_manifest_sha256(m_path, gemini_dir=gem, expedition_dir=exp)
                self.assertEqual(cm.exception.code, exp_code, content)

            # Skip auth file flag and root_dir override.
            m_path.write_text(
                f"{'0'*64}  gemini-antigravity-cli/installation_id\n{da}  expedition/a.txt\n",
                encoding="utf-8",
            )
            res_skip = verify_mod.verify_manifest_sha256(
                m_path, gemini_dir=gem, expedition_dir=exp, skip_auth_files=True
            )
            self.assertEqual(res_skip["entries_checked"], 1)
            self.assertEqual(res_skip["entries_skipped"], 1)
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod.verify_manifest_sha256(
                    m_path, gemini_dir=gem, expedition_dir=exp, skip_auth_files=False
                )
            self.assertEqual(cm.exception.code, "FILE_NOT_FOUND")

            m_root = root / "M_ROOT"
            m_root.write_text(f"{da}  a.txt\n", encoding="utf-8")
            res_r = verify_mod.verify_manifest_sha256(
                m_root, gemini_dir=gem, expedition_dir=exp, root_dir=exp
            )
            self.assertEqual(res_r["entries_checked"], 1)

    def test_03_sqlite_board_swarm_and_cli_full_path(self) -> None:
        cid = "00000000-0000-4000-8000-000000000011"
        wcid = "00000000-0000-4000-8000-000000000022"
        with tempfile.TemporaryDirectory(prefix="alsh_full_") as td:
            root = Path(td)
            manifest, gem, cfg, exp = verify_mod._build_fixture(root, cid, wcid)

            # Full CLI PASS in both JSON and text modes (also exercises default config_dir resolution).
            rc_j, out_j, _ = _capture_main(
                verify_mod,
                [
                    "--manifest", str(manifest),
                    "--gemini-dir", str(gem),
                    "--config-dir", str(cfg),
                    "--expedition-dir", str(exp),
                    "--cid", cid,
                    "--json",
                ],
            )
            self.assertEqual(rc_j, 0)
            self.assertEqual(json.loads(out_j)["status"], "PASS")

            rc_t, out_t, _ = _capture_main(
                verify_mod,
                [
                    "--manifest", str(manifest),
                    "--gemini-dir", str(gem),
                    "--config-dir", str(cfg),
                    "--expedition-dir", str(exp),
                    "--cid", cid,
                ],
            )
            self.assertEqual(rc_t, 0)
            self.assertIn("PASS", out_t)

            # SQLite WAL checks: 0-byte WAL passes; non-empty WAL fails when require_clean_wal=True and passes with False.
            db_p = gem / "conversations" / f"{cid}.db"
            wal_p = Path(f"{db_p}-wal")
            wal_p.write_bytes(b"")
            self.assertEqual(verify_mod.verify_sqlite_databases(gem, require_clean_wal=True)["databases_verified"], 3)
            wal_p.write_bytes(b"dirty_wal_bytes")
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod.verify_sqlite_databases(gem, require_clean_wal=True)
            self.assertEqual(cm.exception.code, "ORPHAN_WAL_NONEMPTY")
            self.assertEqual(verify_mod.verify_sqlite_databases(gem, require_clean_wal=False)["databases_verified"], 3)
            wal_p.unlink()
            # Symlinked WAL rejected.
            wal_p.symlink_to(db_p)
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod.verify_sqlite_databases(gem, require_clean_wal=True)
            self.assertEqual(cm.exception.code, "SYMLINK_FORBIDDEN")
            wal_p.unlink()

            # Empty conversations dir fails with NO_SQLITE_DBS; exact 1-DB boundary passes.
            empty_gem = root / "empty_gem"
            (empty_gem / "conversations").mkdir(parents=True)
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod.verify_sqlite_databases(empty_gem)
            self.assertEqual(cm.exception.code, "NO_SQLITE_DBS")

            one_db = empty_gem / "conversations" / "single.db"
            conn1 = sqlite3.connect(str(one_db))
            conn1.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, x TEXT);")
            conn1.execute("CREATE INDEX idx_x ON t(x);")
            conn1.execute("INSERT INTO t VALUES (1, 'MARKER_ALPHA'), (2, 'MARKER_BETA');")
            conn1.commit()
            conn1.close()
            self.assertEqual(verify_mod.verify_sqlite_databases(empty_gem)["databases_verified"], 1)

            # Corrupt table/index consistency so sqlite3 opens cleanly but PRAGMA integrity_check != [('ok',)].
            raw_db = one_db.read_bytes()
            pos = raw_db.find(b"MARKER_ALPHA")
            self.assertGreater(pos, 0)
            tampered_db = raw_db[:pos] + b"MARKER_ZZZZZ" + raw_db[pos + len(b"MARKER_ALPHA"):]
            one_db.write_bytes(tampered_db)
            with self.assertRaises(verify_mod.IntegrityError) as cm:
                verify_mod.verify_sqlite_databases(empty_gem)
            self.assertEqual(cm.exception.code, "SQLITE_INTEGRITY_FAILED")

            # Board JSONL edge cases: monotonic equal seq passes, regressions/bad start/blank/non-dict/bad fields fail.
            bp = root / "board_test.jsonl"
            bp.write_text(
                '{"seq":1,"agent":"a","text":"x"}\n{"seq":1,"agent":"b","text":"y"}\n',
                encoding="utf-8",
            )
            self.assertEqual(verify_mod.verify_board_jsonl(bp)["messages_verified"], 2)
            for content, exp_code in (
                ("", "EMPTY_BOARD"),
                ('{"seq":1,"agent":"a","text":"x"}', "TRUNCATED_BOARD_LINE"),
                ('{"seq":1,"agent":"a","text":"x"}\n\n', "BLANK_BOARD_LINE"),
                ("[1,2]\n", "BOARD_NOT_OBJECT"),
                ('{"seq":0,"agent":"a","text":"x"}\n', "INVALID_BOARD_SEQ"),
                ('{"seq":true,"agent":"a","text":"x"}\n', "INVALID_BOARD_SEQ"),
                ('{"seq":2,"agent":"a","text":"x"}\n', "BOARD_SEQ_START"),
                ('{"seq":1,"agent":"a","text":"x"}\n{"seq":3,"agent":"a","text":"y"}\n{"seq":2,"agent":"a","text":"z"}\n', "BOARD_SEQ_REGRESSION"),
                ('{"seq":1,"agent":123,"text":"x"}\n', "INVALID_BOARD_AGENT"),
                ('{"seq":1,"agent":"a","text":123}\n', "INVALID_BOARD_TEXT"),
            ):
                bp.write_text(content, encoding="utf-8")
                with self.assertRaises(verify_mod.IntegrityError) as cm:
                    verify_mod.verify_board_jsonl(bp)
                self.assertEqual(cm.exception.code, exp_code, content)

            # Swarm metadata negative checks.
            for bad_cid in ("", "a/b", ".."):
                with self.assertRaises(verify_mod.IntegrityError) as cm:
                    verify_mod.verify_swarm_metadata(gem, bad_cid)
                self.assertEqual(cm.exception.code, "INVALID_CID")

            swarm_dir = gem / "brain" / cid / ".system_generated" / "swarm"
            orig_swarm = (swarm_dir / "swarm.json").read_text(encoding="utf-8")
            orig_members = (swarm_dir / "members.json").read_text(encoding="utf-8")
            for sw_txt, exp_code in (
                ("[]\n", "INVALID_SWARM_JSON"),
                ('{"version":"1","swarm_id":"s"}\n', "INVALID_SWARM_VERSION"),
                ('{"version":1,"swarm_id":""}\n', "INVALID_SWARM_ID"),
            ):
                (swarm_dir / "swarm.json").write_text(sw_txt, encoding="utf-8")
                with self.assertRaises(verify_mod.IntegrityError) as cm:
                    verify_mod.verify_swarm_metadata(gem, cid)
                self.assertEqual(cm.exception.code, exp_code)
            (swarm_dir / "swarm.json").write_text(orig_swarm, encoding="utf-8")

            for mem_txt, exp_code in (
                ("[]\n", "INVALID_MEMBERS_JSON"),
                ('{"members":{}}\n', "INVALID_MEMBERS_MAP"),
                ('{"members":{"a":"bad"}}\n', "INVALID_MEMBER_ENTRY"),
                ('{"members":{"a":{"conversation_id":"","killed":false}}}\n', "INVALID_MEMBER_CID"),
                ('{"members":{"a":{"conversation_id":"../x","killed":false}}}\n', "INVALID_MEMBER_CID"),
                ('{"members":{"a":{"conversation_id":"a/b","killed":false}}}\n', "INVALID_MEMBER_CID"),
            ):
                (swarm_dir / "members.json").write_text(mem_txt, encoding="utf-8")
                with self.assertRaises(verify_mod.IntegrityError) as cm:
                    verify_mod.verify_swarm_metadata(gem, cid)
                self.assertEqual(cm.exception.code, exp_code)
            # Member killed via phase="killed" (even with killed=False) is cleanly skipped.
            (swarm_dir / "members.json").write_text(
                json.dumps({
                    "members": {
                        "coordinator": {"conversation_id": cid, "killed": False, "phase": "waiting"},
                        "old": {"conversation_id": "missing", "killed": False, "phase": "killed"},
                    }
                }) + "\n",
                encoding="utf-8",
            )
            sm_res = verify_mod.verify_swarm_metadata(gem, cid)
            self.assertEqual(sm_res["active_members_verified"], 1)
            self.assertEqual(sm_res["killed_members_skipped"], 1)
            (swarm_dir / "members.json").write_text(orig_members, encoding="utf-8")


class TestToroidHud(unittest.TestCase):
    def test_04_self_test_helpers_and_thresholds(self) -> None:
        rc0, out0, err0 = _capture_main(hud_mod, [])
        self.assertEqual(rc0, 0)
        self.assertEqual(err0, "")
        rc1, out1, err1 = _capture_main(hud_mod, ["--self-test"])
        self.assertEqual(rc1, 0)
        self.assertEqual(err1, "")
        self.assertEqual(out0, out1)
        st = json.loads(out1)
        self.assertEqual(st["status"], "PASS")
        self.assertEqual(st["gpu_ring0_ok"], "OK")
        self.assertIs(st["gpu_ring0_violation_caught"], True)
        self.assertEqual(st["gpu_cpu_host_status"], "none")

        # ASCII uint & ratio formatting.
        self.assertTrue(hud_mod._is_ascii_uint("0"))
        self.assertTrue(hud_mod._is_ascii_uint("90"))
        self.assertFalse(hud_mod._is_ascii_uint(""))
        self.assertFalse(hud_mod._is_ascii_uint("\u0662"))
        self.assertEqual(hud_mod._fmt_ratio_pct(0, 0), "0.0%")
        self.assertEqual(hud_mod._fmt_ratio_pct(1, 50), "2.0%")

        # Strict JSON & board parser refusal checks.
        for raw, exp_code in (
            (" ", "EMPTY_JSON"),
            ("NaN", "JSON_CONSTANT_FORBIDDEN"),
            ("1.2", "JSON_FLOAT_FORBIDDEN"),
            ('{"a":1,"a":2}', "JSON_DUPLICATE_KEY"),
            ("{bad", "JSON_SYNTAX_ERROR"),
        ):
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod.loads_strict_json(raw, "t")
            self.assertEqual(cm.exception.code, exp_code)

        self.assertEqual(hud_mod.parse_board_jsonl_text("\n\n"), [])
        for bad_line, exp_code in (
            ("[1]\n", "BOARD_NOT_OBJECT"),
            ('{"seq":0,"agent":"a","text":"t"}\n', "INVALID_BOARD_SEQ"),
            ('{"seq":true,"agent":"a","text":"t"}\n', "INVALID_BOARD_SEQ"),
            ('{"seq":1,"agent":1,"text":"t"}\n', "INVALID_BOARD_AGENT"),
            ('{"seq":1,"agent":"a","text":1}\n', "INVALID_BOARD_TEXT"),
        ):
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod.parse_board_jsonl_text(bad_line)
            self.assertEqual(cm.exception.code, exp_code)

        # Invalid metric parameters.
        for kw in ({"window_size": 0}, {"window_size": True}, {"max_cartographer_gap": 0}, {"max_weaver_gap": 0}):
            with self.assertRaises(hud_mod.HudError):
                hud_mod.compute_toroid_metrics([], **kw)  # type: ignore[arg-type]

        # Empty board -> CLEAR.
        m_empty = hud_mod.compute_toroid_metrics([])
        self.assertEqual(m_empty["iota_w"], "0/1")
        self.assertEqual(m_empty["gates"]["CS-01"], "CLEAR")

        # Exact CS-01 boundaries: w_len=9 vs 10 with 0 poloidal.
        msgs9 = [{"seq": i, "agent": "worker", "text": "ok"} for i in range(1, 10)]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs9)["gates"]["CS-01"], "WARNING")
        msgs10 = [{"seq": i, "agent": "worker", "text": "ok"} for i in range(1, 11)]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs10)["gates"]["CS-01"], "ALERT")

        # Exact CS-01 poloidal ratio boundary (1/25 CLEAR vs 1/26 WARNING).
        msgs25 = [{"seq": 1, "agent": "session-cartographer", "text": "x"}] + [
            {"seq": i, "agent": "peer-weaver" if i == 2 else "worker", "text": "ok"} for i in range(2, 26)
        ]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs25, window_size=25)["gates"]["CS-01"], "CLEAR")
        msgs26 = [{"seq": 1, "agent": "session-cartographer", "text": "x"}] + [
            {"seq": i, "agent": "worker", "text": "ok"} for i in range(2, 27)
        ]
        # cart_gap=25 (<=40), weav_gap=26 (<=120), n_poloidal=1, w_len=26 -> 25 < 26 -> WARNING!
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs26, window_size=26)["gates"]["CS-01"], "WARNING")

        # Exact CS-01 cart_gap half/full and weav_gap full boundaries.
        msgs_g = [
            {"seq": 1, "agent": "session-cartographer", "text": "c"},
            {"seq": 1, "agent": "peer-weaver", "text": "w"},
            {"seq": 41, "agent": "worker", "text": "x"},
        ]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_g, max_cartographer_gap=80)["gates"]["CS-01"], "CLEAR")
        msgs_g[-1]["seq"] = 42
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_g, max_cartographer_gap=80)["gates"]["CS-01"], "WARNING")
        msgs_g[-1]["seq"] = 81
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_g, max_cartographer_gap=80)["gates"]["CS-01"], "WARNING")
        msgs_g[-1]["seq"] = 82
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_g, max_cartographer_gap=80)["gates"]["CS-01"], "ALERT")
        msgs_w = [
            {"seq": 1, "agent": "peer-weaver", "text": "w"},
            {"seq": 121, "agent": "session-cartographer", "text": "c"},
        ]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_w, max_weaver_gap=120)["gates"]["CS-01"], "CLEAR")
        msgs_w[-1]["seq"] = 122
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_w, max_weaver_gap=120)["gates"]["CS-01"], "ALERT")

        # Exact CS-22 boundaries (0 CLEAR, 1..2 WARNING, 3 ALERT) & CS-23 boundaries (2 CLEAR, 3 WARNING, 10 ALERT).
        msgs_s = [
            {"seq": 1, "agent": "session-cartographer", "text": "Track S1 VERIFIED"},
            {"seq": 2, "agent": "worker", "text": "Track S2 VERIFIED"},
            {"seq": 3, "agent": "worker", "text": "Track S3 FROZEN"},
        ]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_s, atlas_text="Track S1 Track S2 Track S3")["gates"]["CS-22"], "CLEAR")
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_s, atlas_text="Track S1 Track S2")["gates"]["CS-22"], "WARNING")
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_s, atlas_text="")["gates"]["CS-22"], "ALERT")
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_s)["gates"]["CS-23"], "CLEAR")
        msgs_u3 = [{"seq": 1, "agent": "session-cartographer", "text": "fold"}] + [
            {"seq": i, "agent": "worker", "text": "Schur VERIFIED"} for i in range(2, 5)
        ]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_u3)["gates"]["CS-23"], "WARNING")
        msgs_u10 = [{"seq": 1, "agent": "session-cartographer", "text": "fold"}] + [
            {"seq": i, "agent": "worker", "text": "Schur VERIFIED"} for i in range(2, 12)
        ]
        self.assertEqual(hud_mod.compute_toroid_metrics(msgs_u10)["gates"]["CS-23"], "ALERT")

        # Meminfo, GPU CSV, and Roster parsers.
        mem_fb = hud_mod.parse_meminfo_text("IgnoredLine\nMemTotal: 4096 kB\nMemFree: 5120 kB\nSwapTotal: 2048 kB\nSwapFree: 1024 kB\nBad: xyz kB\n")
        self.assertEqual(mem_fb["mem_total_mib"], 4)
        self.assertEqual(mem_fb["mem_used_mib"], 0)
        self.assertEqual(mem_fb["swap_used_mib"], 1)

        with self.assertRaises(hud_mod.HudError) as cm:
            hud_mod.parse_nvidia_smi_output("GPU0, 0, 8192")
        self.assertEqual(cm.exception.code, "INVALID_GPU_CSV")
        with self.assertRaises(hud_mod.HudError) as cm:
            hud_mod.parse_nvidia_smi_output("GPU0, abc, 8192, 40, 0")
        self.assertEqual(cm.exception.code, "INVALID_GPU_METRIC")
        g_no_alert = hud_mod.parse_nvidia_smi_output("RTX 3080, 100, 8192, 45, 5\n", expect_zero_desktop_vram=False)
        self.assertIs(g_no_alert["ring0_vram_alert"], False)
        self.assertEqual(g_no_alert["status"], "OK")

        with self.assertRaises(hud_mod.HudError) as cm:
            hud_mod.summarize_roster({"members": []})  # type: ignore[dict-item]
        self.assertEqual(cm.exception.code, "INVALID_MEMBERS_MAP")
        with self.assertRaises(hud_mod.HudError) as cm:
            hud_mod.summarize_roster({"members": {"a": "bad"}})
        self.assertEqual(cm.exception.code, "INVALID_MEMBER_ENTRY")
        r_sum = hud_mod.summarize_roster({
            "members": {
                "a": {"phase": "RUNNING", "wait_since": 0, "killed": False},
                "b": {"phase": "RUNNING", "wait_since": 100, "killed": False},
                "c": {"phase": "waiting", "killed": False},
                "d": {"phase": "stopped", "killed": False},
                "e": {"phase": "unknown_state", "killed": False},
                "f": {"phase": "killed", "killed": False},
                "g": {"phase": "waiting", "killed": True},
            }
        })
        self.assertEqual(r_sum, {"total": 7, "working": 1, "waiting": 2, "stopped": 2, "killed": 2})

    def test_05_hud_io_cli_watch_and_auto_discover(self) -> None:
        with tempfile.TemporaryDirectory(prefix="alsh_hud_") as td:
            root = Path(td)
            # IO refusal sites in hud_mod.
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._split_safe_parts(Path("x\x00y"), "t")
            self.assertEqual(cm.exception.code, "NUL_PATH")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._split_safe_parts(Path("a/../b"), "t")
            self.assertEqual(cm.exception.code, "PATH_TRAVERSAL")
            self.assertEqual(hud_mod._split_safe_parts(Path("./rel"), "t")[-1], "rel")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(Path("/"), "t")
            self.assertEqual(cm.exception.code, "NOT_REGULAR_FILE")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(root, "t")
            self.assertEqual(cm.exception.code, "NOT_REGULAR_FILE")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(root / "no_dir" / "f", "t")
            self.assertEqual(cm.exception.code, "FILE_NOT_FOUND")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(root / "missing.txt", "t")
            self.assertEqual(cm.exception.code, "FILE_NOT_FOUND")

            sub = root / "sub"
            sub.mkdir()
            okf = sub / "f.txt"
            okf.write_bytes(b"1234")
            sym_d = root / "symd"
            sym_d.symlink_to(sub)
            sym_f = root / "symf"
            sym_f.symlink_to(okf)
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(sym_d / "f.txt", "t")
            self.assertEqual(cm.exception.code, "SYMLINK_FORBIDDEN")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(sym_f, "t")
            self.assertEqual(cm.exception.code, "SYMLINK_FORBIDDEN")
            self.assertEqual(hud_mod._read_regular_text(okf, "t", max_bytes=4), "1234")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(okf, "t", max_bytes=3)
            self.assertEqual(cm.exception.code, "FILE_TOO_LARGE")
            badu = sub / "u.bin"
            badu.write_bytes(b"\xff\xfe")
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod._read_regular_text(badu, "t")
            self.assertEqual(cm.exception.code, "INVALID_UTF8")
            if os.geteuid() != 0:
                nr = sub / "nr.txt"
                nr.write_text("x", encoding="utf-8")
                nr.chmod(0o000)
                nd = root / "nd"
                nd.mkdir(mode=0o000)
                try:
                    with self.assertRaises(hud_mod.HudError) as cm:
                        hud_mod._read_regular_text(nr, "t")
                    self.assertEqual(cm.exception.code, "IO_ERROR")
                    with self.assertRaises(hud_mod.HudError) as cm:
                        hud_mod._read_regular_text(nd / "x", "t")
                    self.assertEqual(cm.exception.code, "IO_ERROR")
                finally:
                    nr.chmod(0o600)
                    nd.chmod(0o700)

            # Synthetic swarm + auto_discover + snapshot + ANSI + CLI --once / --watch.
            gdir = root / "ag"
            sdir = gdir / "brain" / "cid1" / ".system_generated" / "swarm"
            sdir.mkdir(parents=True)
            with self.assertRaises(hud_mod.HudError) as cm:
                hud_mod.auto_discover_swarm(gdir)
            self.assertEqual(cm.exception.code, "SWARM_NOT_FOUND")

            bp = sdir / "board.jsonl"
            bp.write_text(
                json.dumps({"seq": 1, "agent": "session-cartographer", "text": "Mapped Track S1 VERIFIED"}) + "\n",
                encoding="utf-8",
            )
            mp = sdir / "members.json"
            mp.write_text(
                json.dumps({"members": {"coordinator": {"phase": "working", "killed": False}}}) + "\n",
                encoding="utf-8",
            )
            ap = root / "atlas.md"
            ap.write_text("# Atlas\nTrack S1\n", encoding="utf-8")
            memp = root / "meminfo"
            memp.write_text("MemTotal: 32768000 kB\nMemAvailable: 16384000 kB\n", encoding="utf-8")

            snap_gpu = hud_mod.collect_snapshot(
                board_path=bp,
                members_path=mp,
                atlas_path=ap,
                meminfo_path=memp,
                gpu_csv_override="RTX 3080, 0, 8192, 41, 0\n",
                expect_zero_desktop_vram=True,
            )
            self.assertEqual(snap_gpu["gpu"]["status"], "OK")
            ansi_gpu = hud_mod.render_ansi_dashboard(snap_gpu)
            self.assertIn("RTX 3080", ansi_gpu)

            snap_nogpu = hud_mod.collect_snapshot(
                board_path=bp,
                members_path=None,
                atlas_path=None,
                meminfo_path=root / "absent_meminfo",
                gpu_csv_override="",
            )
            self.assertIn("CPU-only", hud_mod.render_ansi_dashboard(snap_nogpu))

            # Stub nvidia-smi binaries test probe_gpu_live exit 0 vs non-zero cleanly on CPU-only hosts.
            smi_ok = root / "fake-nvidia-ok"
            smi_ok.write_text("#!/usr/bin/env bash\nprintf 'RTX 3080, 0, 8192, 41, 0\\n'\n", encoding="utf-8")
            smi_ok.chmod(0o755)
            smi_fail = root / "fake-nvidia-fail"
            smi_fail.write_text("#!/usr/bin/env bash\nprintf 'not_valid_csv\\n'\nexit 1\n", encoding="utf-8")
            smi_fail.chmod(0o755)
            self.assertEqual(
                hud_mod.probe_gpu_live(expect_zero_desktop_vram=True, nvidia_smi_bin=str(smi_ok))["status"], "OK"
            )
            self.assertEqual(
                hud_mod.probe_gpu_live(expect_zero_desktop_vram=True, nvidia_smi_bin=str(smi_fail))["status"], "none"
            )
            self.assertEqual(
                hud_mod.probe_gpu_live(nvidia_smi_bin=str(root / "no-such-nvidia-smi"))["status"], "none"
            )

            # CLI --once --json, --once ANSI, --watch --max-iterations 1, and invalid flags.
            rc_j, out_j, _ = _capture_main(
                hud_mod,
                ["--once", "--json", "--auto-discover", "--gemini-dir", str(gdir), "--atlas", str(ap), "--meminfo-path", str(memp)],
            )
            self.assertEqual(rc_j, 0)
            self.assertEqual(json.loads(out_j)["toroid"]["head_seq"], 1)

            rc_a, out_a, _ = _capture_main(
                hud_mod, ["--once", "--board", str(bp), "--members", str(mp), "--meminfo-path", str(memp)]
            )
            self.assertEqual(rc_a, 0)
            self.assertIn("ALETHEIA CONTINUAL-TOROID HUD", out_a)

            rc_w, out_w, _ = _capture_main(
                hud_mod,
                ["--watch", "--interval", "1", "--max-iterations", "1", "--board", str(bp), "--meminfo-path", str(memp)],
            )
            self.assertEqual(rc_w, 0)
            self.assertIn("Board Head: #1", out_w)

            for bad_argv, exp_code in (
                (["--once"], "MISSING_BOARD"),
                (["--once", "--board", str(bp), "--interval", "0"], "INVALID_INTERVAL"),
                (["--once", "--board", str(bp), "--max-iterations", "-1"], "INVALID_ITERATIONS"),
            ):
                rc_e, out_e, _ = _capture_main(hud_mod, bad_argv + ["--json"])
                self.assertEqual(rc_e, 2)
                self.assertEqual(json.loads(out_e)["code"], exp_code)
                rc_et, _, err_et = _capture_main(hud_mod, bad_argv)
                self.assertEqual(rc_et, 2)
                self.assertIn(exp_code, err_et)


class TestShellScripts(unittest.TestCase):
    def test_06_bash_syntax_dry_runs_and_restore_roundtrip(self) -> None:
        scripts = [
            BIN_DIR / "freeze-for-migration.sh",
            BIN_DIR / "restore-and-verify.sh",
            BIN_DIR / "bootstrap-zenbook.sh",
        ]
        for sp in scripts:
            proc = subprocess.run(["bash", "-n", str(sp)], capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, f"bash -n failed on {sp.name}: {proc.stderr}")

        # bootstrap-zenbook.sh --dry-run
        p_boot = subprocess.run(
            ["bash", str(BIN_DIR / "bootstrap-zenbook.sh"), "--dry-run", "--ml-os-dir", "/tmp/nonexistent-mlos"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(p_boot.returncode, 0, p_boot.stderr)
        self.assertIn("DRY-RUN", p_boot.stdout)
        self.assertIn("COMPLETE", p_boot.stdout)

        # Synthetic bundle for freeze --dry-run and full restore-and-verify.sh (dry-run + live restore!).
        cid = "00000000-0000-4000-8000-0000000000aa"
        wcid = "00000000-0000-4000-8000-0000000000bb"
        with tempfile.TemporaryDirectory(prefix="alsh_sh_") as td:
            root = Path(td)
            src_home_gem = root / "src_gemini"
            src_ag = src_home_gem / "antigravity-cli"
            src_cfg = src_home_gem / "config"
            src_exp = root / "src_exp"
            bundle = root / "bundle"
            payload = bundle / "payload"

            manifest, _, _, _ = verify_mod._build_fixture(payload, cid, wcid)
            # Move manifest to bundle root and write complete MIGRATION_RECEIPT.json seal
            m_bytes = manifest.read_bytes()
            (bundle / "MIGRATION_SHA256SUMS").write_bytes(m_bytes)
            manifest.unlink()
            p_files = [p for p in payload.rglob("*") if p.is_file() and not p.is_symlink()]
            (bundle / "MIGRATION_RECEIPT.json").write_text(
                json.dumps(
                    {
                        "schema": "aletheia.migration_receipt.v1",
                        "cid": cid,
                        "mode": "full",
                        "file_count": len(p_files),
                        "total_bytes": sum(p.stat().st_size for p in p_files),
                        "manifest_sha256": hashlib.sha256(m_bytes).hexdigest(),
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            # Populate source dirs for freeze-for-migration.sh --dry-run
            src_home_gem.mkdir(parents=True)
            subprocess.run(["cp", "-a", str(payload / "gemini-antigravity-cli"), str(src_ag)], check=True)
            subprocess.run(["cp", "-a", str(payload / "gemini-config"), str(src_cfg)], check=True)
            subprocess.run(["cp", "-a", str(payload / "expedition"), str(src_exp)], check=True)

            p_frz = subprocess.run(
                [
                    "bash",
                    str(BIN_DIR / "freeze-for-migration.sh"),
                    "--dest",
                    str(root / "dry_dest"),
                    "--gemini-dir",
                    str(src_home_gem),
                    "--expedition-dir",
                    str(src_exp),
                    "--slim",
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_frz.returncode, 0, p_frz.stderr)
            self.assertIn("DRY-RUN", p_frz.stdout)
            self.assertIn(cid, p_frz.stdout)

            # restore-and-verify.sh --dry-run
            dst_gem = root / "dst_gemini"
            dst_exp = root / "dst_exp"
            p_rdry = subprocess.run(
                [
                    "bash",
                    str(BIN_DIR / "restore-and-verify.sh"),
                    "--src",
                    str(bundle),
                    "--gemini-dir",
                    str(dst_gem),
                    "--expedition-dir",
                    str(dst_exp),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_rdry.returncode, 0, p_rdry.stderr)
            self.assertIn(f"agy --resume {cid}", p_rdry.stdout)

            # Live restore-and-verify.sh into fresh target preserving target installation_id & stripping stale lock!
            (dst_gem / "antigravity-cli" / "presence").mkdir(parents=True)
            (dst_gem / "antigravity-cli" / "presence" / "stale.lock").write_text("stale\n", encoding="utf-8")
            (dst_gem / "antigravity-cli" / "installation_id").write_text("target-host-id\n", encoding="utf-8")
            p_rlive = subprocess.run(
                [
                    "bash",
                    str(BIN_DIR / "restore-and-verify.sh"),
                    "--src",
                    str(bundle),
                    "--gemini-dir",
                    str(dst_gem),
                    "--expedition-dir",
                    str(dst_exp),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_rlive.returncode, 0, f"restore failed: {p_rlive.stdout}\n{p_rlive.stderr}")
            self.assertIn("RESTORE VERIFIED PASS", p_rlive.stdout)
            self.assertIn(f"agy --resume {cid}", p_rlive.stdout)
            self.assertEqual(
                (dst_gem / "antigravity-cli" / "installation_id").read_text(encoding="utf-8"),
                "target-host-id\n",
            )
            self.assertFalse((dst_gem / "antigravity-cli" / "presence" / "stale.lock").exists())

    def test_07_screenpad_hud_launcher_omarchy_lua_and_silicon_probe(self) -> None:
        launcher = BIN_DIR / "launch-screenpad-hud.sh"
        self.assertTrue(launcher.is_file())
        p_syn = subprocess.run(["bash", "-n", str(launcher)], capture_output=True, text=True, check=False)
        self.assertEqual(p_syn.returncode, 0, p_syn.stderr)

        p_help = subprocess.run(["bash", str(launcher), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(p_help.returncode, 0, p_help.stderr)
        self.assertIn("DP-3", p_help.stdout)
        self.assertIn("workspace 11", p_help.stdout)

        p_dry = subprocess.run(
            [
                "bash",
                str(launcher),
                "--dry-run",
                "--workspace",
                "11",
                "--monitor",
                "DP-3",
                "--terminal",
                "foot",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(p_dry.returncode, 0, p_dry.stderr)
        self.assertIn("DRY-RUN MONITOR=DP-3 WORKSPACE=11", p_dry.stdout)
        self.assertIn("hl.dsp.exec_cmd(", p_dry.stdout)
        self.assertIn("workspace 11 silent", p_dry.stdout)
        self.assertIn("toroid-hud.py", p_dry.stdout)

        # Mocked hyprctl tests: Omarchy 4.5.0 Lua backend, classic Hyprland fallback (rc=7 on Lua), and fail-closed.
        with tempfile.TemporaryDirectory(prefix="alsh_hypr_mock_") as td:
            fake_bin = Path(td)
            fake_term = fake_bin / "foot"
            fake_term.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            fake_term.chmod(0o755)
            log_file = fake_bin / "hyprctl.log"

            # (a) Omarchy 4.5.0 Lua hyprctl accepts hl.dsp.exec_cmd(...) on first call.
            fake_hypr = fake_bin / "hyprctl"
            fake_hypr.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$*\" >> '{log_file}'\n"
                'if [[ "$1" == "dispatch" && "$2" == hl.dsp.exec_cmd\\(* ]]; then\n'
                '  echo "ok"\n'
                "  exit 0\n"
                "fi\n"
                "exit 7\n",
                encoding="utf-8",
            )
            fake_hypr.chmod(0o755)
            env_mock = {**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
            p_lua = subprocess.run(
                ["bash", str(launcher), "--workspace", "11", "--monitor", "DP-3", "--terminal", "foot"],
                capture_output=True,
                text=True,
                env=env_mock,
                check=False,
            )
            self.assertEqual(p_lua.returncode, 0, p_lua.stderr)
            self.assertIn("backend=omarchy-lua", p_lua.stdout)
            lua_calls = log_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lua_calls), 1)
            self.assertIn("hl.dsp.exec_cmd(", lua_calls[0])
            self.assertIn("[workspace 11 silent]", lua_calls[0])

            # (b) Classic Hyprland rejects Lua dispatch with rc=7 and falls back cleanly to dispatch exec.
            log_file.unlink()
            fake_hypr.write_text(
                "#!/usr/bin/env bash\n"
                f"printf '%s\\n' \"$*\" >> '{log_file}'\n"
                'if [[ "$1" == "dispatch" && "$2" == "exec" ]]; then\n'
                '  echo "ok"\n'
                "  exit 0\n"
                "fi\n"
                "exit 7\n",
                encoding="utf-8",
            )
            p_classic = subprocess.run(
                ["bash", str(launcher), "--workspace", "11", "--monitor", "DP-3", "--terminal", "foot"],
                capture_output=True,
                text=True,
                env=env_mock,
                check=False,
            )
            self.assertEqual(p_classic.returncode, 0, p_classic.stderr)
            self.assertIn("backend=classic-hyprland", p_classic.stdout)
            classic_calls = log_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(classic_calls), 2)
            self.assertIn("hl.dsp.exec_cmd(", classic_calls[0])
            self.assertTrue(classic_calls[1].startswith("dispatch exec [workspace 11 silent]"))

            # (c) Both backends failing must fail closed with non-zero exit code.
            fake_hypr.write_text("#!/usr/bin/env bash\nexit 7\n", encoding="utf-8")
            p_fail = subprocess.run(
                ["bash", str(launcher), "--workspace", "11", "--monitor", "DP-3", "--terminal", "foot"],
                capture_output=True,
                text=True,
                env=env_mock,
                check=False,
            )
            self.assertNotEqual(p_fail.returncode, 0)
            self.assertIn("ERROR: hyprctl failed", p_fail.stderr)

        # Invalid arguments must fail closed with rc=2.
        for bad_args in (
            ["--workspace", "0"],
            ["--interval", "abc"],
            ["--window", "-5"],
            ["--monitor", "DP-3;rm"],
            ["--unknown-flag"],
        ):
            p_bad = subprocess.run(["bash", str(launcher), *bad_args], capture_output=True, text=True, check=False)
            self.assertEqual(p_bad.returncode, 2, f"expected rc=2 for {bad_args}, got {p_bad.returncode}")

        # --once --json works end-to-end against a synthetic swarm directory.
        with tempfile.TemporaryDirectory(prefix="alsh_launch_") as td:
            root = Path(td)
            sdir = root / "ag" / "brain" / "cid1" / ".system_generated" / "swarm"
            sdir.mkdir(parents=True)
            (sdir / "board.jsonl").write_text(
                json.dumps({"seq": 1, "agent": "session-cartographer", "text": "Mapped Track S1 VERIFIED"}) + "\n",
                encoding="utf-8",
            )
            atlas_p = root / "atlas.md"
            atlas_p.write_text("# Atlas\nTrack S1\n", encoding="utf-8")
            p_once = subprocess.run(
                [
                    "bash",
                    str(launcher),
                    "--once",
                    "--json",
                    "--gemini-dir",
                    str(root / "ag"),
                    "--atlas",
                    str(atlas_p),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_once.returncode, 0, p_once.stderr)
            snap = json.loads(p_once.stdout)
            self.assertEqual(snap["status"], "OK")
            self.assertEqual(snap["toroid"]["head_seq"], 1)

        # Live-verified Omarchy 4.5.0 Lua snippet & CUDA sm_86 silicon probe checks.
        lua_path = ROOT / "configs" / "omarchy-4.5-ux582hs-monitors.lua"
        self.assertTrue(lua_path.is_file())
        lua_txt = lua_path.read_text(encoding="utf-8")
        self.assertIn('output = "eDP-1"', lua_txt)
        self.assertIn('output = "DP-3"', lua_txt)
        self.assertIn('mode = "3840x1100@60"', lua_txt)
        self.assertIn('position = "0x1080"', lua_txt)
        self.assertIn('name = "elan9009:00-04f3:2c23"', lua_txt)
        self.assertIn('name = "elan9008:00-04f3:2c56"', lua_txt)

        cu_path = ROOT / "bench" / "rtx3080_sm86_silicon_probe.cu"
        self.assertTrue(cu_path.is_file())
        cu_raw = cu_path.read_bytes()
        self.assertNotIn(b"\r", cu_raw)
        cu_txt = cu_raw.decode("utf-8")
        self.assertIn("hamming_a16_syndrome_decode_kernel", cu_txt)
        self.assertIn("block_h2_int8_kernel", cu_txt)
        self.assertNotIn("/" + "home" + "/", cu_txt)


if __name__ == "__main__":
    unittest.main()
