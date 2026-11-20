import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rotation import (  # noqa: E402
    Credential,
    Finding,
    Policy,
    age_days,
    check_rotation,
    load_snapshot,
    main,
)

AS_OF = date(2026, 11, 20)


class RotationTests(unittest.TestCase):
    def test_age_days(self):
        cred = Credential("example-api", "2026-11-10", "team-a")
        self.assertEqual(age_days(cred, AS_OF), 10)

    def test_fresh_credentials_not_reported(self):
        creds = [
            Credential("fresh", "2026-11-19", "team-a"),
            Credential("boundary", "2026-08-22", "team-b"),  # exactly 90 days
        ]
        self.assertEqual(check_rotation(creds, Policy(90), AS_OF), [])

    def test_overdue_reported_with_age(self):
        creds = [Credential("stale", "2026-01-10", "team-a")]
        findings = check_rotation(creds, Policy(90), AS_OF)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].age_days, 314)
        self.assertEqual(findings[0].overdue_by_days, 224)
        self.assertEqual(findings[0].severity, "high")

    def test_medium_severity_within_one_window(self):
        creds = [Credential("slightly-late", "2026-08-01", "team-b")]
        findings = check_rotation(creds, Policy(90), AS_OF)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_future_date_produces_negative_age(self):
        cred = Credential("skewed", "2026-12-01", "team-c")
        self.assertEqual(age_days(cred, AS_OF), -11)
        self.assertEqual(check_rotation([cred], Policy(90), AS_OF), [])

    def test_load_snapshot(self):
        data = {
            "policy": {"max_age_days": 30},
            "credentials": [
                {"service": "svc", "last_rotated": "2026-01-01", "owner": "team-x"}
            ],
        }
        policy, creds = load_snapshot(data)
        self.assertEqual(policy, Policy(30))
        self.assertEqual(creds, [Credential("svc", "2026-01-01", "team-x")])

    def test_invalid_date_raises(self):
        cred = Credential("bad", "not-a-date", "team-a")
        with self.assertRaises(ValueError):
            age_days(cred, AS_OF)

    def test_finding_is_immutable(self):
        finding = Finding("svc", "team", "2026-01-01", 100, 10, "medium")
        with self.assertRaises(Exception):
            finding.severity = "high"  # type: ignore[misc]

    def test_cli(self):
        snapshot = {
            "policy": {"max_age_days": 90},
            "credentials": [
                {"service": "stale", "last_rotated": "2026-01-10", "owner": "team-a"}
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            self.assertEqual(
                main([str(path), "--as-of", AS_OF.isoformat()]), 0
            )
            self.assertEqual(
                main([str(path), "--as-of", AS_OF.isoformat(), "--max-age", "400"]), 0
            )
            self.assertEqual(main([str(path), "--as-of", "bad-date"]), 2)


if __name__ == "__main__":
    unittest.main()
