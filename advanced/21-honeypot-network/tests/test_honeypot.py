import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from honeypot import (  # noqa: E402
    Analysis,
    HoneypotEvent,
    Thresholds,
    analyze,
    generate_events,
    load_events,
    main,
    render,
)


def connect_events(source: str, ports: range, gap_seconds: int) -> tuple[HoneypotEvent, ...]:
    base = datetime(2026, 3, 1, 10, 0, 0)
    return tuple(
        HoneypotEvent(
            (base + timedelta(seconds=index * gap_seconds)).isoformat(timespec="seconds"),
            source,
            "tcp-probe",
            port,
            "connect",
        )
        for index, port in enumerate(ports)
    )


def auth_events(source: str, failures: int, successes: int) -> tuple[HoneypotEvent, ...]:
    base = datetime(2026, 3, 1, 11, 0, 0)
    items = [
        HoneypotEvent(
            (base + timedelta(seconds=index)).isoformat(timespec="seconds"),
            source,
            "ssh",
            22,
            "auth_failure",
            f"user-{index:03d}",
            "wordlist-a",
        )
        for index in range(failures)
    ]
    items.extend(
        HoneypotEvent(
            (base + timedelta(seconds=100 + index)).isoformat(timespec="seconds"),
            source,
            "ssh",
            22,
            "auth_success",
            f"valid-{index:03d}",
            "wordlist-a",
        )
        for index in range(successes)
    )
    return tuple(items)


class HoneypotTests(unittest.TestCase):
    def test_generated_events_are_deterministic(self):
        self.assertEqual(generate_events(), generate_events())
        self.assertEqual(len(generate_events(seed=3)), len(generate_events(seed=3)))
        self.assertNotEqual(generate_events(seed=3), generate_events(seed=4))

    def test_sample_analysis_finds_all_planted_patterns(self):
        analysis = analyze(generate_events())
        kinds = {finding.kind for finding in analysis.findings}
        self.assertTrue({"scanning", "credential-stuffing", "repeated-source"}.issubset(kinds))
        self.assertEqual(analysis.event_count, len(generate_events()))
        self.assertEqual(analysis.source_count, len({e.source_ip for e in generate_events()}))

    def test_scanning_respects_time_window(self):
        spread = connect_events("192.0.2.10", range(5000, 5005), 600)
        self.assertEqual(analyze(spread).findings, ())
        tight = connect_events("192.0.2.11", range(5000, 5005), 20)
        findings = analyze(tight).findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "scanning")
        self.assertEqual(findings[0].source_ip, "192.0.2.11")

    def test_scanning_port_threshold(self):
        small = connect_events("192.0.2.12", range(5000, 5004), 20)
        self.assertEqual(analyze(small).findings, ())
        self.assertEqual(len(analyze(small, Thresholds(scan_ports=4)).findings), 1)

    def test_stuffing_success_ratio_guard(self):
        mixed = auth_events("203.0.113.10", 6, 3)
        quiet = Thresholds(repeated_events=99)
        self.assertEqual(analyze(mixed, quiet).findings, ())
        findings = analyze(mixed, Thresholds(max_success_ratio=0.5, repeated_events=99)).findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "credential-stuffing")

    def test_stuffing_username_threshold(self):
        few = auth_events("203.0.113.11", 4, 0)
        self.assertEqual(analyze(few).findings, ())
        self.assertEqual(len(analyze(few, Thresholds(stuffing_usernames=4)).findings), 1)

    def test_repeated_source_threshold(self):
        events = connect_events("192.0.2.20", range(6000, 6007), 1200)
        self.assertEqual(analyze(events).findings, ())
        more = connect_events("192.0.2.20", range(6000, 6008), 1200)
        findings = analyze(more).findings
        self.assertEqual([finding.kind for finding in findings], ["repeated-source"])
        self.assertEqual(findings[0].count, 8)

    def test_findings_are_sorted_by_severity(self):
        findings = analyze(generate_events()).findings
        ranks = {"high": 1, "medium": 2}
        values = [ranks[f.severity] for f in findings]
        self.assertEqual(values, sorted(values))

    def test_load_events_and_render(self):
        data = {
            "events": [
                {
                    "timestamp": "2026-03-01T10:00:00",
                    "source_ip": "192.0.2.30",
                    "service": "ssh",
                    "port": 22,
                    "event_type": "auth_failure",
                    "username": "user-001",
                    "credential_label": "wordlist-a",
                }
            ]
        }
        events = load_events(data)
        self.assertEqual(events[0].username, "user-001")
        analysis = analyze(events)
        self.assertIsInstance(analysis, Analysis)
        text = render(analysis)
        self.assertIn("HONEYPOT ANALYSIS (simulated)", text)
        self.assertIn("No findings above", text)

    def test_cli_sample_and_analyze_file(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["sample", "--json"])
        self.assertEqual(code, 0)
        self.assertGreater(len(json.loads(out.getvalue())), 0)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture.json"
            path.write_text(json.dumps({"events": [e.__dict__ for e in generate_events()]}), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["analyze", str(path)])
            self.assertEqual(code, 0)
            self.assertIn("scanning", out.getvalue())


if __name__ == "__main__":
    unittest.main()
