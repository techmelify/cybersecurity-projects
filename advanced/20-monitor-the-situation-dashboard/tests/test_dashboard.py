import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dashboard import Event, generate_sample_events, load_events, main, render, summarize  # noqa: E402


EVENTS = (
    Event("2026-01-12T08:01:00", "auth-gateway", "critical", "auth", "a"),
    Event("2026-01-12T08:14:00", "auth-gateway", "HIGH", "auth", "b"),
    Event("2026-01-12T08:16:00", "ids-edge-01", "low", "network", "c"),
    Event("2026-01-12T08:47:00", "ids-edge-01", "low", "network", "d"),
    Event("2026-01-12T09:02:00", "endpoint-agent", "trace", "endpoint", "e"),
)


class DashboardTests(unittest.TestCase):
    def test_severity_counts_use_canonical_order(self):
        report = summarize(EVENTS)
        self.assertEqual(report.total, 5)
        self.assertEqual(report.severity_counts[:3], (("critical", 1), ("high", 1), ("low", 2)))
        self.assertEqual(report.elevated, 2)

    def test_unknown_severity_sorted_last(self):
        report = summarize(EVENTS)
        self.assertEqual(report.severity_counts[-1], ("trace", 1))

    def test_top_sources_deterministic_ties(self):
        report = summarize(EVENTS, top_n=3)
        self.assertEqual(report.top_sources[0], ("auth-gateway", 2))
        self.assertEqual(report.top_sources[1], ("ids-edge-01", 2))
        self.assertEqual([name for name, _ in report.top_sources], ["auth-gateway", "ids-edge-01", "endpoint-agent"])

    def test_top_n_limit(self):
        self.assertEqual(len(summarize(EVENTS, top_n=1).top_sources), 1)
        with self.assertRaises(ValueError):
            summarize(EVENTS, top_n=0)

    def test_buckets_are_floored_and_gaps_filled(self):
        report = summarize(EVENTS, bucket_minutes=15)
        self.assertEqual([bucket.start[11:16] for bucket in report.timeline], ["08:00", "08:15", "08:30", "08:45", "09:00"])
        self.assertEqual([bucket.count for bucket in report.timeline], [2, 1, 0, 1, 1])
        self.assertEqual(summarize(EVENTS, bucket_minutes=30).timeline[0].count, 3)

    def test_render_contains_sections(self):
        text = render(summarize(EVENTS))
        for section in ("SITUATION DASHBOARD", "Severity:", "Top sources:", "Timeline (15m buckets):"):
            self.assertIn(section, text)
        self.assertIn("critical", text)
        self.assertIn("08:30", text)

    def test_sample_feed_is_deterministic(self):
        first = generate_sample_events()
        second = generate_sample_events()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 48)
        self.assertEqual(summarize(first).total, summarize(second).total)

    def test_load_events_wrapper(self):
        data = {
            "events": [
                {
                    "timestamp": "2026-01-12T08:00:00Z",
                    "source": "s",
                    "severity": "high",
                    "category": "auth",
                    "message": "m",
                }
            ]
        }
        events = load_events(data)
        self.assertEqual(events[0].source, "s")
        self.assertEqual(summarize(events).severity_counts, (("high", 1),))

    def test_cli_and_empty_input(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--sample", "--top", "3", "--bucket-minutes", "30"])
        self.assertEqual(code, 0)
        self.assertIn("SITUATION DASHBOARD", out.getvalue())
        self.assertEqual(summarize([]).timeline, ())
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--sample", "feed.json"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.json"
            path.write_text(json.dumps([]), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([str(path)])
            self.assertEqual(code, 0)
            self.assertIn("Events: 0", out.getvalue())


if __name__ == "__main__":
    unittest.main()
