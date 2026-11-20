import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threat_detector import (  # noqa: E402
    Baseline,
    DetectorConfig,
    Event,
    Rule,
    build_baseline,
    default_rules,
    demo_data,
    detect,
    detection_to_dict,
    main,
    score_event,
)


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.baseline_events = (
            Event("b1", {"x": 2.0, "y": 10.0}),
            Event("b2", {"x": 4.0, "y": 20.0}),
            Event("b3", {"x": 3.0, "y": 30.0}),
        )
        self.baseline = build_baseline(self.baseline_events)

    def test_build_baseline_statistics(self):
        self.assertAlmostEqual(self.baseline.means["x"], 3.0)
        self.assertAlmostEqual(self.baseline.stddevs["x"], (2.0 / 3.0) ** 0.5)
        self.assertAlmostEqual(self.baseline.means["y"], 20.0)

    def test_baseline_needs_two_vectors(self):
        with self.assertRaises(ValueError):
            build_baseline((Event("only", {"x": 1.0}),))

    def test_baseline_feature_sets_must_match(self):
        with self.assertRaises(ValueError):
            build_baseline((Event("a", {"x": 1.0}), Event("b", {"y": 2.0})))

    def test_zero_stddev_behaviour(self):
        baseline = build_baseline((Event("a", {"x": 5.0}), Event("b", {"x": 5.0})))
        config = DetectorConfig(rules=())
        same = score_event(Event("same", {"x": 5.0}), baseline, config)
        different = score_event(Event("diff", {"x": 9.0}), baseline, config)
        self.assertEqual(same.z_scores["x"], 0.0)
        self.assertEqual(different.z_scores["x"], 10.0)
        self.assertTrue(different.suspicious)

    def test_rule_above_trigger(self):
        rule = Rule("high", "failed_logins", above=5, score=3)
        self.assertTrue(rule.matches(6.0))
        self.assertFalse(rule.matches(5.0))
        self.assertIn("failed_logins", rule.description())

    def test_rule_below_trigger(self):
        rule = Rule("low", "score", below=0.0)
        self.assertTrue(rule.matches(-1.0))
        self.assertFalse(rule.matches(0.0))

    def test_rule_requires_threshold(self):
        with self.assertRaises(ValueError):
            Rule("empty", "x")

    def test_suspicious_by_z_score(self):
        result = score_event(Event("e", {"x": 100.0, "y": 20.0}), self.baseline, DetectorConfig(rules=()))
        self.assertTrue(result.suspicious)
        self.assertGreater(result.anomaly_score, 2.5)
        self.assertTrue(any("z_score" in reason for reason in result.reasons))

    def test_suspicious_by_rule_only(self):
        result = score_event(
            Event("e", {"x": 3.0, "y": 20.0, "failed_logins": 9, "bytes_out": 100.0, "admin_actions": 0}),
            self.baseline,
            DetectorConfig(rules=default_rules()),
        )
        self.assertTrue(result.suspicious)
        self.assertEqual(result.triggered_rules, ("many-failed-logins",))
        self.assertFalse(result.z_scores["x"] >= 2.5)

    def test_normal_event_not_suspicious(self):
        result = score_event(
            Event("e", {"x": 3.0, "y": 20.0, "failed_logins": 0, "bytes_out": 100.0, "admin_actions": 0}),
            self.baseline,
            DetectorConfig(rules=default_rules()),
        )
        self.assertFalse(result.suspicious)
        self.assertEqual(result.reasons, ())

    def test_missing_feature_raises(self):
        with self.assertRaises(ValueError):
            score_event(Event("e", {"x": 3.0}), self.baseline, DetectorConfig(rules=()))

    def test_detect_preserves_order(self):
        events = (Event("a", {"x": 3.0, "y": 20.0}), Event("b", {"x": 9.0, "y": 20.0}))
        results = detect(events, self.baseline, DetectorConfig(rules=()))
        self.assertEqual([r.event_id for r in results], ["a", "b"])
        self.assertEqual([r.suspicious for r in results], [False, True])

    def test_detection_to_dict(self):
        result = score_event(Event("e", {"x": 3.0, "y": 20.0}), self.baseline, DetectorConfig(rules=()))
        payload = detection_to_dict(result)
        self.assertEqual(payload["event_id"], "e")
        self.assertEqual(payload["triggered_rules"], [])
        self.assertFalse(payload["suspicious"])

    def test_cli_demo_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--demo", "--json", "--suspicious-only"])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["suspicious"], 1)
        self.assertEqual([d["event_id"] for d in report["detections"]], ["spike-1"])

    def test_cli_custom_files_and_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            events_path = root / "events.json"
            rules_path = root / "rules.json"
            baseline_path.write_text(json.dumps([{"event_id": "b1", "features": {"x": 1}}, {"event_id": "b2", "features": {"x": 3}}]), encoding="utf-8")
            events_path.write_text(json.dumps([{"event_id": "e1", "features": {"x": 2}}]), encoding="utf-8")
            rules_path.write_text(json.dumps([{"name": "x-high", "feature": "x", "above": 1.5, "score": 1}]), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["--baseline", str(baseline_path), "--events", str(events_path), "--rules", str(rules_path), "--json"])
            self.assertEqual(code, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["detections"][0]["triggered_rules"], ["x-high"])

    def test_cli_requires_inputs(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([]), 1)


if __name__ == "__main__":
    unittest.main()
