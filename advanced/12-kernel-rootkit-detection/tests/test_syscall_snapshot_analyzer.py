import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from syscall_snapshot_analyzer import (  # noqa: E402
    analyze_snapshot,
    load_snapshot,
    main,
    parse_snapshot,
)

CLEAN = {
    "allowed_modules": ["kernel", "ext4"],
    "syscalls": [
        {
            "number": 1,
            "name": "write",
            "handler": "sys_write",
            "expected_handler": "sys_write",
            "module": "kernel",
        }
    ],
    "processes": [
        {
            "pid": 1,
            "name": "init",
            "visible_in_proc": True,
            "listed_by_ps": True,
            "hidden": False,
        }
    ],
}


class SyscallSnapshotAnalyzerTests(unittest.TestCase):
    def test_clean_snapshot_has_no_detections(self):
        self.assertEqual(analyze_snapshot(parse_snapshot(CLEAN)).detections, ())

    def test_hook_mismatch_is_critical(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["syscalls"][0]["handler"] = "0xffffffffc0123450"
        detections = analyze_snapshot(parse_snapshot(snapshot)).detections
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].rule_id, "KRN-HOOK-001")
        self.assertEqual(detections[0].severity, "critical")

    def test_unexpected_module_owner_is_high(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["syscalls"][0]["module"] = "mystery.ko"
        detections = analyze_snapshot(parse_snapshot(snapshot)).detections
        self.assertEqual([detection.rule_id for detection in detections], ["KRN-MOD-001"])
        self.assertEqual(detections[0].severity, "high")

    def test_process_hidden_from_proc_view_is_high(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["processes"][0]["visible_in_proc"] = False
        detections = analyze_snapshot(parse_snapshot(snapshot)).detections
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].severity, "high")
        self.assertIn("proc view", detections[0].message)

    def test_process_hidden_from_ps_listing_is_high(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["processes"][0]["listed_by_ps"] = False
        detections = analyze_snapshot(parse_snapshot(snapshot)).detections
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].severity, "high")

    def test_process_hidden_from_both_views_is_critical(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["processes"][0]["visible_in_proc"] = False
        snapshot["processes"][0]["listed_by_ps"] = False
        detections = analyze_snapshot(parse_snapshot(snapshot)).detections
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].severity, "critical")

    def test_explicit_hidden_flag_is_detected(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["processes"][0]["hidden"] = True
        detections = analyze_snapshot(parse_snapshot(snapshot)).detections
        self.assertEqual(len(detections), 1)
        self.assertIn("explicit hidden flag", detections[0].message)

    def test_detections_are_deterministically_sorted(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["syscalls"][0]["handler"] = "0xbad"
        snapshot["syscalls"][0]["module"] = "mystery.ko"
        snapshot["processes"][0]["listed_by_ps"] = False
        report = analyze_snapshot(parse_snapshot(snapshot))
        self.assertEqual(report, analyze_snapshot(parse_snapshot(snapshot)))
        self.assertEqual(
            [detection.rule_id for detection in report.detections],
            ["KRN-HOOK-001", "KRN-MOD-001", "KRN-PROC-001"],
        )

    def test_report_counts_and_dict_note(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["syscalls"][0]["module"] = "mystery.ko"
        payload = analyze_snapshot(parse_snapshot(snapshot)).to_dict()
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["counts"]["high"], 1)
        self.assertIn("no kernel access", payload["note"])

    def test_parse_rejects_bad_pid_type(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["processes"][0]["pid"] = "one"
        with self.assertRaises(ValueError):
            parse_snapshot(snapshot)

    def test_load_snapshot_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text("42", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_snapshot(path)

    def test_cli_json_output(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["syscalls"][0]["handler"] = "0xbad"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["total"], 1)

    def test_cli_fail_on_critical_returns_one(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["processes"][0]["visible_in_proc"] = False
        snapshot["processes"][0]["listed_by_ps"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
                code = main([str(path), "--fail-on", "critical"])
            self.assertEqual(code, 1)

    def test_cli_missing_file_returns_one(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            code = main(["missing.json"])
        self.assertEqual(code, 1)
        self.assertIn("error:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
