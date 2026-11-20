import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wireless_deauth_detector import (  # noqa: E402
    DetectionConfig,
    detect_floods,
    main,
    parse_event,
    parse_events,
    reason_description,
)

STA = "02:00:00:00:00:01"
STA2 = "02:00:00:00:00:02"
STA3 = "02:00:00:00:00:03"
AP = "02:00:00:00:00:99"


def frame(second, receiver=STA, ap=AP, kind="deauth", reason=7):
    return f"2026-11-20T10:00:{second:02d}Z {kind} receiver={receiver} ap={ap} reason={reason} rssi=-55"


class WirelessDeauthDetectorTests(unittest.TestCase):
    def test_parse_event_fields(self):
        event = parse_event(frame(5))
        self.assertEqual(event.kind, "deauth")
        self.assertEqual(event.receiver, STA)
        self.assertEqual(event.bssid, AP)
        self.assertEqual(event.reason, 7)
        self.assertEqual(event.rssi, -55)
        self.assertEqual(event.time.isoformat(), "2026-11-20T10:00:05")

    def test_parse_disassoc_event(self):
        event = parse_event(frame(1, kind="disassoc", reason=4))
        self.assertEqual(event.kind, "disassoc")
        self.assertEqual(reason_description(event.reason), "disassociated due to inactivity")

    def test_unrelated_lines_are_ignored(self):
        self.assertEqual(parse_events(["garbage", "", "beacon receiver=" + STA]), ())

    def test_invalid_mac_is_rejected(self):
        bad = f"2026-11-20T10:00:00Z deauth receiver=not-a-mac ap={AP} reason=7"
        with self.assertRaises(ValueError):
            parse_event(bad)

    def test_unknown_reason_description(self):
        self.assertIn("999", reason_description(999))

    def test_receiver_flood_detected(self):
        events = parse_events(frame(second) for second in range(9))
        report = detect_floods(events)
        self.assertEqual(len(report.receiver_alerts), 1)
        self.assertEqual(report.receiver_alerts[0].count, 9)
        self.assertEqual(report.receiver_alerts[0].reasons, (7,))
        self.assertEqual(report.ap_alerts, ())
        self.assertIn("receiver flood", report.receiver_alerts[0].message)

    def test_no_alert_below_threshold(self):
        events = parse_events(frame(second) for second in range(7))
        self.assertTrue(detect_floods(events).ok)

    def test_frames_grouped_by_receiver(self):
        lines = [frame(second, receiver=STA) for second in range(4)]
        lines += [frame(second, receiver=STA2) for second in range(4)]
        report = detect_floods(parse_events(lines))
        self.assertEqual(report.receiver_alerts, ())
        self.assertEqual(report.total_events, 8)

    def test_sliding_window_excludes_old_frames(self):
        lines = [frame(0)]
        lines += [frame(second, reason=9) for second in range(20, 28)]
        config = DetectionConfig(receiver_threshold=8, receiver_window=timedelta(seconds=10))
        report = detect_floods(parse_events(lines), config)
        self.assertEqual(len(report.receiver_alerts), 1)
        self.assertEqual(report.receiver_alerts[0].count, 8)
        self.assertEqual(report.receiver_alerts[0].first_seen.isoformat(), "2026-11-20T10:00:20")

    def test_ap_flood_across_receivers(self):
        lines = []
        for second in range(7):
            for receiver in (STA, STA2, STA3):
                lines.append(frame(second, receiver=receiver))
        report = detect_floods(parse_events(lines))
        self.assertEqual(len(report.ap_alerts), 1)
        self.assertEqual(report.ap_alerts[0].unique_receivers, 3)
        self.assertEqual(report.receiver_alerts, ())

    def test_critical_severity_escalation(self):
        events = parse_events(frame(second % 9) for second in range(16))
        self.assertEqual(detect_floods(events).receiver_alerts[0].severity, "critical")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.log"
            path.write_text("\n".join(frame(second) for second in range(9)), encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 1)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["receiver_alerts"][0]["count"], 9)

    def test_cli_clean_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.log"
            path.write_text(frame(0) + "\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(path)])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
