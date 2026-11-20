import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from finding_tracker import (  # noqa: E402
    CvssVector,
    Finding,
    Tracker,
    can_transition,
    cvss_like_score,
    main,
    severity_for_score,
    transition,
)


def vector(**overrides):
    values = CvssVector().__dict__.copy()
    values.update(overrides)
    return CvssVector(**values)


def finding(fid="F-001", status="open", **overrides):
    return Finding(fid, "Lab finding", "https://lab.example", "synthetic", vector(**overrides), status)


class TrackerTests(unittest.TestCase):
    def test_known_cvss_like_score(self):
        high = vector(confidentiality="high", integrity="high", availability="high")
        self.assertEqual(cvss_like_score(high), 9.8)

    def test_zero_impact_score(self):
        self.assertEqual(cvss_like_score(vector(confidentiality="none", integrity="none")), 0.0)

    def test_severity_bands(self):
        self.assertEqual(severity_for_score(0.0), "none")
        self.assertEqual(severity_for_score(3.9), "low")
        self.assertEqual(severity_for_score(4.0), "medium")
        self.assertEqual(severity_for_score(7.0), "high")
        self.assertEqual(severity_for_score(9.0), "critical")
        with self.assertRaises(ValueError):
            severity_for_score(11.0)

    def test_invalid_vector_value(self):
        with self.assertRaises(ValueError):
            vector(attack_vector="internet")

    def test_transition_rules(self):
        self.assertTrue(can_transition("open", "triaged"))
        self.assertFalse(can_transition("open", "closed"))
        self.assertFalse(can_transition("unknown", "open"))
        updated = transition(finding(), "triaged")
        self.assertEqual(updated.status, "triaged")
        self.assertEqual(finding().status, "open")

    def test_invalid_transition_raises(self):
        with self.assertRaises(ValueError):
            transition(finding(), "closed")

    def test_add_and_list_sorted(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = Tracker(Path(directory) / "store.json")
            tracker.add(finding("F-2"))
            tracker.add(finding("F-1"))
            self.assertEqual([f.finding_id for f in tracker.list_findings()], ["F-1", "F-2"])

    def test_duplicate_id_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = Tracker(Path(directory) / "store.json")
            tracker.add(finding())
            with self.assertRaises(ValueError):
                tracker.add(finding())

    def test_persistence_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "store.json"
            Tracker(path).add(finding(confidentiality="high", integrity="high", availability="high"))
            loaded = Tracker(path).get("F-001")
            self.assertEqual(loaded.score, 9.8)
            self.assertEqual(loaded.severity, "critical")

    def test_status_persists(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "store.json"
            tracker = Tracker(path)
            tracker.add(finding())
            tracker.set_status("F-001", "triaged")
            self.assertEqual(Tracker(path).get("F-001").status, "triaged")

    def test_export_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracker = Tracker(root / "store.json")
            tracker.add(finding("F-1"))
            tracker.add(finding("F-2", confidentiality="high", integrity="high", availability="high"))
            report = tracker.export(root / "report.json")
            self.assertEqual(report["total"], 2)
            self.assertEqual(report["by_severity"]["critical"], 1)
            written = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(written["findings"][0]["severity"], "medium")

    def test_missing_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = Tracker(Path(directory) / "store.json")
            with self.assertRaises(KeyError):
                tracker.get("nope")

    def test_cli_add_status_list_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / "store.json"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([str(store), "add", "F-9", "CLI finding", "lab://target", "--c", "high", "--i", "high", "--a", "high"]), 0)
                self.assertEqual(main([str(store), "status", "F-9", "triaged"]), 0)
                self.assertEqual(main([str(store), "list", "--json"]), 0)
                self.assertEqual(main([str(store), "export", str(root / "report.json")]), 0)
            self.assertIn("added F-9: 9.8 (critical)", output.getvalue())
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["findings"][0]["status"], "triaged")


if __name__ == "__main__":
    unittest.main()
