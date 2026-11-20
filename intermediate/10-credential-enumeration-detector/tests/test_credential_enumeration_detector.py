import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from credential_enumeration_detector import (  # noqa: E402
    DetectorConfig,
    LoginResult,
    analyze,
    build_signatures,
    load_results,
    main,
    normalize_message,
)


def dataset(status=401, message="Invalid credentials", timing=(50.0, 50.0), count=3):
    results = []
    for index, user in enumerate(("alice", "bob")):
        for _ in range(count):
            results.append(LoginResult(user, "failure", status, message, timing[index]))
    return results


class CredentialEnumerationDetectorTests(unittest.TestCase):
    def test_normalize_message(self):
        self.assertEqual(normalize_message("  Invalid   CREDENTIALS \n"), "invalid credentials")

    def test_build_signatures(self):
        signatures = build_signatures(dataset())
        self.assertEqual(len(signatures), 2)
        self.assertEqual(signatures[0].username, "alice")
        self.assertEqual(signatures[0].observations, 3)
        self.assertEqual(signatures[0].status_codes, (401,))
        self.assertEqual(signatures[0].median_ms, 50.0)

    def test_clean_dataset_has_no_findings(self):
        report = analyze(dataset())
        self.assertFalse(report.vulnerable)
        self.assertEqual(report.findings, ())
        self.assertEqual(report.total_results, 6)

    def test_status_code_differential(self):
        results = []
        for user, status in (("alice", 401), ("bob", 200)):
            for _ in range(3):
                results.append(LoginResult(user, "failure", status, "Invalid credentials", 50.0))
        findings = analyze(results).findings
        self.assertEqual([f.kind for f in findings], ["status_code_differential"])
        self.assertIn("bob", findings[0].evidence[1])

    def test_message_differential(self):
        results = []
        for user, message in (("alice", "Invalid username"), ("bob", "Invalid password")):
            for _ in range(3):
                results.append(LoginResult(user, "failure", 401, message, 50.0))
        self.assertEqual([f.kind for f in analyze(results).findings], ["message_differential"])

    def test_timing_differential(self):
        findings = analyze(dataset(timing=(200.0, 40.0))).findings
        self.assertEqual([f.kind for f in findings], ["timing_differential"])
        self.assertIn("5.00x", findings[0].detail)

    def test_small_timing_gap_is_ignored(self):
        self.assertEqual(analyze(dataset(timing=(52.0, 50.0))).findings, ())

    def test_min_observations_filters_single_attempts(self):
        results = [
            LoginResult("alice", "failure", 401, "Invalid", 50.0),
            LoginResult("bob", "failure", 200, "Different", 90.0),
        ]
        self.assertEqual(analyze(results).findings, ())

    def test_min_users_requirement(self):
        results = [
            LoginResult("alice", "failure", 401, "Invalid one", 50.0),
            LoginResult("alice", "failure", 200, "Invalid two", 90.0),
        ]
        self.assertEqual(analyze(results).findings, ())

    def test_success_results_are_ignored(self):
        results = dataset()
        results += [
            LoginResult("carol", "success", 200, "Welcome", 10.0),
            LoginResult("carol", "success", 201, "Welcome again", 10.0),
        ]
        self.assertEqual(analyze(results).findings, ())

    def test_custom_config(self):
        config = DetectorConfig(min_observations=1, timing_delta_ms=10.0, timing_ratio=1.1)
        results = [
            LoginResult("alice", "failure", 401, "Same", 52.0),
            LoginResult("bob", "failure", 401, "Same", 40.0),
        ]
        self.assertTrue(analyze(results, config).vulnerable)

    def test_load_results_validation(self):
        valid = [
            {
                "username": "alice",
                "outcome": "failure",
                "status_code": 401,
                "message": "Invalid",
                "duration_ms": 50,
            }
        ]
        self.assertEqual(load_results(valid)[0].duration_ms, 50.0)
        with self.assertRaises(ValueError):
            load_results({"username": "alice"})
        with self.assertRaises(ValueError):
            load_results([{"username": "alice"}])

    def test_cli_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "results.json"
            records = [
                {
                    "username": user,
                    "outcome": "failure",
                    "status_code": status,
                    "message": message,
                    "duration_ms": duration,
                }
                for user, status, message, duration in (
                    ("alice", 401, "Invalid credentials", 200.0),
                    ("bob", 200, "Invalid credentials", 40.0),
                )
                for _ in range(3)
            ]
            path.write_text(json.dumps(records), encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json", "--strict"])
            self.assertEqual(code, 1)
            self.assertTrue(json.loads(buffer.getvalue())["findings"])

    def test_cli_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "results.json"
            records = [
                {
                    "username": user,
                    "outcome": "failure",
                    "status_code": 401,
                    "message": "Invalid credentials",
                    "duration_ms": 50.0,
                }
                for user in ("alice", "bob")
                for _ in range(3)
            ]
            path.write_text(json.dumps(records), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(path)])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
