import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector import AuthEvent, detect_brute_force, main, parse_auth_log  # noqa: E402


def fail(minute, ip="192.0.2.10", user="root"):
    return f"Nov 20 10:{minute:02d}:00 host sshd[1]: Failed password for {user} from {ip} port 1 ssh2"


def success(minute, ip="192.0.2.10", user="root"):
    return f"Nov 20 10:{minute:02d}:00 host sshd[1]: Accepted password for {user} from {ip} port 1 ssh2"


class DetectorTests(unittest.TestCase):
    def test_parse_fail_and_success(self):
        events = parse_auth_log([fail(0), success(1)])
        self.assertEqual([e.kind for e in events], ["fail", "success"])
        self.assertEqual(events[0].ip, "192.0.2.10")
        self.assertEqual(events[0].user, "root")

    def test_invalid_user_pattern(self):
        line = "Nov 20 10:00:00 host sshd[1]: Failed password for invalid user admin from 198.51.100.5 port 1 ssh2"
        self.assertEqual(parse_auth_log([line])[0].user, "admin")

    def test_ignores_unrelated_lines(self):
        self.assertEqual(parse_auth_log(["garbage", "Nov 99 99:99:99 bad"]), [])

    def test_alert_after_threshold(self):
        events = [AuthEvent(datetime(2026, 11, 20, 10, i), "fail", "root", "192.0.2.10") for i in range(6)]
        alerts = detect_brute_force(events, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failures, 6)
        self.assertFalse(alerts[0].followed_by_success)

    def test_no_alert_below_threshold(self):
        events = [AuthEvent(datetime(2026, 11, 20, 10, i), "fail", "root", "192.0.2.10") for i in range(4)]
        self.assertEqual(detect_brute_force(events, threshold=5), [])

    def test_window_excludes_old_failures(self):
        base = datetime(2026, 11, 20, 10, 0)
        events = [AuthEvent(base, "fail", "root", "192.0.2.10")]
        events += [AuthEvent(base + timedelta(minutes=20 + i), "fail", "root", "192.0.2.10") for i in range(5)]
        alerts = detect_brute_force(events, threshold=5, window=timedelta(minutes=5))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failures, 5)

    def test_success_after_brute_force(self):
        events = [AuthEvent(datetime(2026, 11, 20, 10, i), "fail", "root", "192.0.2.10") for i in range(5)]
        events.append(AuthEvent(datetime(2026, 11, 20, 10, 6), "success", "root", "192.0.2.10"))
        self.assertTrue(detect_brute_force(events, threshold=5)[0].followed_by_success)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.log"
            path.write_text("\n".join(fail(i) for i in range(6)), encoding="utf-8")
            self.assertEqual(main([str(path), "--threshold", "5"]), 0)


if __name__ == "__main__":
    unittest.main()
