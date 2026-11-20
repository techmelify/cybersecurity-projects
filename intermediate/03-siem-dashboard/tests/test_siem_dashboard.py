import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from siem_dashboard import (  # noqa: E402
    Alert,
    Event,
    correlate,
    format_dashboard,
    load_events,
    main,
    parse_event,
    parse_events,
)


def record(
    event_type="info",
    source_ip="192.0.2.10",
    user="alice",
    severity="low",
    when="2026-11-20T12:00:00Z",
    host="host-1",
    message="synthetic fixture",
):
    return json.dumps({
        "timestamp": when,
        "event_type": event_type,
        "source_ip": source_ip,
        "user": user,
        "host": host,
        "severity": severity,
        "message": message,
    })


def event(event_type="info", source_ip="192.0.2.10", user="alice", severity="low", hour=12):
    return Event(
        datetime(2026, 11, 20, hour, tzinfo=timezone.utc),
        event_type,
        source_ip,
        user,
        "host-1",
        severity,
        "synthetic fixture",
    )


class ParseTests(unittest.TestCase):
    def test_parse_event_fields(self):
        parsed = parse_event(record(event_type="Failed_Login", severity="HIGH"))
        self.assertEqual(parsed.event_type, "failed_login")
        self.assertEqual(parsed.severity, "high")
        self.assertEqual(parsed.source_ip, "192.0.2.10")
        self.assertEqual(parsed.timestamp.date().isoformat(), "2026-11-20")

    def test_parse_event_defaults(self):
        parsed = parse_event("{}")
        self.assertIsNone(parsed.timestamp)
        self.assertEqual(parsed.event_type, "unknown")
        self.assertEqual(parsed.source_ip, "unknown")
        self.assertEqual(parsed.severity, "info")

    def test_alias_keys(self):
        parsed = parse_event('{"time":"2026-11-20T01:00:00Z","type":"login","ip":"192.0.2.99"}')
        self.assertEqual(parsed.event_type, "login")
        self.assertEqual(parsed.source_ip, "192.0.2.99")
        self.assertEqual(parsed.timestamp.hour, 1)

    def test_invalid_json(self):
        with self.assertRaises(ValueError):
            parse_event("not json", line_number=3)

    def test_non_object(self):
        with self.assertRaises(ValueError):
            parse_event("[1, 2]", line_number=4)

    def test_bad_timestamp(self):
        with self.assertRaises(ValueError):
            parse_event('{"timestamp":"yesterday"}', line_number=5)

    def test_blank_lines_skipped(self):
        lines = [record(), "", "   ", record(event_type="login")]
        self.assertEqual(len(parse_events(lines)), 2)

    def test_load_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(record() + "\n" + record(event_type="login"), encoding="utf-8")
            self.assertEqual(len(load_events(path)), 2)


class CorrelateTests(unittest.TestCase):
    def test_counts_are_deterministic(self):
        dashboard = correlate([
            event("login", "192.0.2.2"),
            event("login", "192.0.2.1"),
            event("alert", "192.0.2.1", severity="high"),
        ])
        self.assertEqual(list(dashboard.by_type.items()), [("login", 2), ("alert", 1)])
        self.assertEqual(list(dashboard.by_source.items()), [("192.0.2.1", 2), ("192.0.2.2", 1)])
        self.assertEqual(dashboard.total, 3)

    def test_failed_login_burst_boundary(self):
        failures = [event("failed_login") for _ in range(4)]
        self.assertEqual(correlate(failures, threshold=5).alerts, ())
        dashboard = correlate(failures + [event("failed_login")], threshold=5)
        alerts = [alert for alert in dashboard.alerts if alert.rule == "failed_login_burst"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "high")
        self.assertEqual(alerts[0].count, 5)

    def test_failed_login_bursts_are_per_source(self):
        events = [event("failed_login", "192.0.2.10") for _ in range(5)]
        events += [event("failed_login", "192.0.2.11") for _ in range(2)]
        dashboard = correlate(events, threshold=5)
        rules = [alert.detail for alert in dashboard.alerts if alert.rule == "failed_login_burst"]
        self.assertEqual(rules, ["192.0.2.10: 5 failed logins"])

    def test_high_severity_alert(self):
        dashboard = correlate([event(severity="critical"), event(severity="high"), event()])
        alerts = [alert for alert in dashboard.alerts if alert.rule == "high_severity_events"]
        self.assertEqual(alerts[0].count, 2)
        self.assertEqual(alerts[0].severity, "high")

    def test_off_hours_alert(self):
        events = [event(hour=23) for _ in range(4)] + [event(hour=5)]
        dashboard = correlate(events, threshold=5)
        self.assertTrue(any(alert.rule == "off_hours_activity" for alert in dashboard.alerts))
        self.assertFalse(any(a.rule == "off_hours_activity" for a in correlate(events[:4], threshold=5).alerts))

    def test_many_failed_users(self):
        events = [
            event("failed_login", user=f"user-{index}")
            for index in range(4)
        ]
        dashboard = correlate(events, threshold=4)
        self.assertTrue(any(alert.rule == "many_failed_users" for alert in dashboard.alerts))

    def test_firewall_block_burst(self):
        dashboard = correlate([event("firewall_block") for _ in range(6)], threshold=5)
        alerts = [alert for alert in dashboard.alerts if alert.rule == "firewall_block_burst"]
        self.assertEqual(alerts[0].severity, "low")
        self.assertEqual(alerts[0].count, 6)

    def test_empty_events(self):
        dashboard = correlate([])
        self.assertEqual(dashboard.total, 0)
        self.assertEqual(dashboard.alerts, ())
        self.assertEqual(dashboard.top_sources, ())

    def test_alerts_sorted_by_severity_then_rule(self):
        events = [event("failed_login") for _ in range(5)] + [event(severity="high")]
        rules = [alert.rule for alert in correlate(events, threshold=5).alerts]
        self.assertEqual(rules, ["failed_login_burst", "high_severity_events"])

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            correlate([], threshold=0)

    def test_report_sections(self):
        empty_report = format_dashboard(correlate([]))
        self.assertIn("Total events: 0", empty_report)
        self.assertIn("By type:\n  none", empty_report)
        self.assertIn("Alerts:\n  none", empty_report)
        filled = format_dashboard(correlate([event(severity="high")]))
        self.assertIn("[HIGH", filled)


class CliTests(unittest.TestCase):
    def test_cli_text_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(record(event_type="failed_login", severity="high") + "\n", encoding="utf-8")
            text_buffer = io.StringIO()
            with redirect_stdout(text_buffer):
                self.assertEqual(main([str(path)]), 0)
            self.assertIn("Total events: 1", text_buffer.getvalue())

            json_buffer = io.StringIO()
            with redirect_stdout(json_buffer):
                self.assertEqual(main([str(path), "--json", "--threshold", "1"]), 0)
            payload = json.loads(json_buffer.getvalue())
            self.assertEqual(payload["total"], 1)
            self.assertTrue(payload["alerts"])

    def test_cli_missing_file(self):
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(Path(tmp) / "none.jsonl")]), 2)


if __name__ == "__main__":
    unittest.main()
