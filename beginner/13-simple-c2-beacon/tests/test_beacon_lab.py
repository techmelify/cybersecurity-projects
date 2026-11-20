import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from beacon_lab import detect_beacons, generate_beacons, main  # noqa: E402


class BeaconTests(unittest.TestCase):
    def test_generate_count_and_order(self):
        times = generate_beacons(5, interval=60, jitter=0)
        self.assertEqual(len(times), 5)
        self.assertEqual(times, sorted(times))
        self.assertEqual((times[1] - times[0]).total_seconds(), 60)

    def test_jitter_is_bounded(self):
        times = generate_beacons(10, interval=60, jitter=0.2, seed=1)
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        self.assertTrue(all(48 <= g <= 72 for g in gaps))

    def test_bad_params(self):
        with self.assertRaises(ValueError):
            generate_beacons(0)
        with self.assertRaises(ValueError):
            generate_beacons(5, interval=0)

    def test_regular_beacon_detected(self):
        times = generate_beacons(12, interval=30, jitter=0.02, seed=3)
        result = detect_beacons(times)
        self.assertTrue(result.suspicious)
        self.assertAlmostEqual(result.interval_seconds, 30, delta=2)

    def test_random_events_not_detected(self):
        base = datetime(2026, 11, 20, tzinfo=timezone.utc)
        times = [base + timedelta(seconds=i * i * 7 + i * 13) for i in range(8)]
        self.assertFalse(detect_beacons(times).suspicious)

    def test_too_few_events(self):
        result = detect_beacons([datetime(2026, 1, 1)])
        self.assertIsNone(result.interval_seconds)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "times.txt"
            times = generate_beacons(6, jitter=0)
            path.write_text("\n".join(t.isoformat() for t in times), encoding="utf-8")
            self.assertEqual(main(["detect", str(path)]), 0)
            self.assertEqual(main(["simulate", "-n", "3"]), 0)


if __name__ == "__main__":
    unittest.main()
