import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from race_detector import (  # noqa: E402
    AccessEvent,
    analyze_code,
    analyze_timeline,
    load_events,
    main,
)


def event(second: int, subject: str, phase: str, resource: str = "/tmp/report"):
    return AccessEvent(f"2026-01-01T00:00:{second:02d}", subject, resource, phase)


class RaceDetectorTests(unittest.TestCase):
    def test_different_subject_in_window_is_reported(self):
        events = [event(0, "alice", "check"), event(1, "bob", "act")]
        findings = analyze_timeline(events, window_seconds=5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "timeline-toctou")
        self.assertEqual(findings[0].subject, "bob")
        self.assertEqual(findings[0].severity, "high")

    def test_same_subject_is_not_a_race(self):
        events = [event(0, "alice", "check"), event(1, "alice", "act")]
        self.assertEqual(analyze_timeline(events, window_seconds=5), [])

    def test_act_outside_window_is_ignored(self):
        events = [event(0, "alice", "check"), event(10, "bob", "act")]
        self.assertEqual(analyze_timeline(events, window_seconds=5), [])

    def test_act_before_check_is_ignored(self):
        events = [event(0, "bob", "act"), event(5, "alice", "check")]
        self.assertEqual(analyze_timeline(events, window_seconds=5), [])

    def test_resources_are_isolated(self):
        events = [
            event(0, "alice", "check", "/tmp/a"),
            event(1, "bob", "act", "/tmp/b"),
        ]
        self.assertEqual(analyze_timeline(events, window_seconds=5), [])

    def test_larger_gap_is_medium(self):
        events = [event(0, "alice", "check"), event(4, "bob", "act")]
        findings = analyze_timeline(events, window_seconds=5)
        self.assertEqual(findings[0].severity, "medium")

    def test_code_pattern_detected(self):
        sources = {"app.py": "if os.path.exists(p):\n    handle = open(p)\n"}
        findings = analyze_code(sources)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "code-toctou")
        self.assertEqual(findings[0].target, "app.py")

    def test_code_without_act_is_clean(self):
        sources = {"app.py": "if access(p):\n    print('ok')\n"}
        self.assertEqual(analyze_code(sources), [])

    def test_load_events(self):
        data = [{"timestamp": "2026-01-01T00:00:00", "subject": "a", "resource": "r", "phase": "CHECK"}]
        self.assertEqual(load_events(data), [AccessEvent("2026-01-01T00:00:00", "a", "r", "check")])

    def test_cli(self):
        events = [
            {"timestamp": "2026-01-01T00:00:00", "subject": "alice", "resource": "r", "phase": "check"},
            {"timestamp": "2026-01-01T00:00:01", "subject": "bob", "resource": "r", "phase": "act"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            event_path = base / "events.json"
            code_path = base / "sources.json"
            event_path.write_text(json.dumps(events), encoding="utf-8")
            code_path.write_text(json.dumps({"app.py": "if exists(p):\n    open(p)\n"}), encoding="utf-8")
            self.assertEqual(main(["timeline", str(event_path), "--window", "5"]), 0)
            self.assertEqual(main(["code", str(code_path)]), 0)
            self.assertEqual(main(["code", str(event_path)]), 2)


if __name__ == "__main__":
    unittest.main()
