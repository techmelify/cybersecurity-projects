import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from covert_channel_detector import (  # noqa: E402
    ChannelAssessment,
    PacketEvent,
    assess,
    demo_logs,
    main,
    parse_events,
)


def regular_log(count: int = 12) -> tuple[PacketEvent, ...]:
    return tuple(PacketEvent(float(i), 200 + i * 17) for i in range(count))


def jittered_log() -> tuple[PacketEvent, ...]:
    times = []
    current = 0.0
    for index in range(12):
        times.append(current)
        current += 0.5 if index % 2 else 1.5
    return tuple(PacketEvent(t, 200 + index * 17) for index, t in enumerate(times))


def burst_log() -> tuple[PacketEvent, ...]:
    events = []
    for base in (0.0, 10.0, 20.0):
        for offset in (0.0, 0.1, 0.2):
            events.append(PacketEvent(base + offset, 300 + len(events) * 13))
    return tuple(events)


class CovertChannelDetectorTests(unittest.TestCase):
    def test_parse_events_aliases_and_validation(self):
        events = parse_events([{"t": 0, "bytes": 100}, {"timestamp": 1.5, "size": 200}])
        self.assertEqual(events[1].timestamp, 1.5)
        with self.assertRaises(ValueError):
            parse_events([{"t": 1, "size": 10}, {"t": 0, "size": 10}])
        with self.assertRaises(ValueError):
            parse_events([{"t": 0, "size": 0}])
        with self.assertRaises(ValueError):
            parse_events([{"t": 0}])

    def test_regular_timing(self):
        report = assess(regular_log())
        signals = {signal.name for signal in report.signals}
        self.assertIn("regular-timing", signals)
        self.assertEqual(report.verdict, "suspicious")

    def test_jittered_timing_not_flagged(self):
        report = assess(jittered_log())
        self.assertNotIn("regular-timing", {signal.name for signal in report.signals})
        self.assertEqual(report.verdict, "benign")

    def test_size_encoding(self):
        events = tuple(PacketEvent(float(i), 100 if i % 2 == 0 else 101) for i in range(12))
        report = assess(events)
        self.assertIn("size-encoding", {signal.name for signal in report.signals})

    def test_varied_sizes_not_flagged(self):
        self.assertNotIn(
            "size-encoding",
            {signal.name for signal in assess(regular_log()).signals},
        )

    def test_low_rate_bursts(self):
        report = assess(burst_log())
        signals = {signal.name for signal in report.signals}
        self.assertIn("low-rate-bursts", signals)
        self.assertNotIn("regular-timing", signals)

    def test_combined_signals_reach_likely_covert(self):
        events = tuple(PacketEvent(float(i), 100 if i % 2 == 0 else 101) for i in range(12))
        report = assess(events)
        self.assertEqual(report.score, 5)
        self.assertEqual(report.verdict, "likely-covert")

    def test_short_logs_are_benign(self):
        report = assess((PacketEvent(0.0, 100), PacketEvent(1.0, 101)))
        self.assertEqual(report.signals, ())
        self.assertEqual(report.verdict, "benign")
        self.assertEqual(report.events_analyzed, 2)

    def test_demo_logs_are_stable_and_different(self):
        demos = demo_logs()
        self.assertEqual(set(demos), {"benign", "covert-pattern"})
        self.assertEqual(assess(demos["benign"]).verdict, "benign")
        self.assertEqual(assess(demos["covert-pattern"]).verdict, "likely-covert")
        self.assertIsInstance(assess(demos["benign"]), ChannelAssessment)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.json"
            path.write_text(
                json.dumps([{"t": i, "size": 100 + (i % 2)} for i in range(12)]),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                self.assertEqual(main(["--file", str(path)]), 0)
            self.assertEqual(json.loads(buffer.getvalue())["verdict"], "likely-covert")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["--demo"]), 0)
        self.assertIn("benign", json.loads(buffer.getvalue()))


if __name__ == "__main__":
    unittest.main()
