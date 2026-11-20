import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from compliance_dashboard import (  # noqa: E402
    check_missing_logging,
    check_over_permissive_iam,
    check_public_buckets,
    check_unencrypted_volumes,
    evaluate_snapshot,
    load_snapshot,
    main,
)

CLEAN = {
    "buckets": [
        {
            "name": "private-logs",
            "acl": "private",
            "public_read": False,
            "public_write": False,
            "public_access_block": True,
        }
    ],
    "iam_policies": [
        {
            "name": "readonly",
            "statements": [
                {
                    "effect": "Allow",
                    "principal": "arn:example:role/reader",
                    "actions": ["s3:GetObject"],
                    "resources": ["arn:example:bucket/private-logs/*"],
                }
            ],
        }
    ],
    "volumes": [{"id": "vol-1", "encrypted": True}],
    "logging": {
        "cloudtrail_enabled": True,
        "vpc_flow_logs_enabled": True,
        "s3_access_logging_enabled": True,
    },
}


class ComplianceDashboardTests(unittest.TestCase):
    def test_clean_snapshot_has_no_findings(self):
        self.assertEqual(evaluate_snapshot(CLEAN).findings, ())

    def test_public_read_bucket_is_high(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["buckets"][0]["public_read"] = True
        findings = check_public_buckets(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("public read", findings[0].message)

    def test_public_write_bucket_is_critical(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["buckets"][0]["public_write"] = True
        findings = check_public_buckets(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_public_access_block_disabled_is_medium(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["buckets"][0]["public_access_block"] = False
        findings = check_public_buckets(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_admin_iam_statement_is_critical(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["iam_policies"] = [
            {
                "name": "admin",
                "statements": [
                    {
                        "effect": "Allow",
                        "principal": "*",
                        "actions": ["*"],
                        "resources": ["*"],
                    }
                ],
            }
        ]
        findings = check_over_permissive_iam(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_wildcard_action_for_any_principal_is_high(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["iam_policies"] = [
            {
                "name": "bucket-admin",
                "statements": [
                    {
                        "effect": "Allow",
                        "principal": "*",
                        "actions": ["s3:*"],
                        "resources": ["arn:example:bucket/private-logs/*"],
                    }
                ],
            }
        ]
        findings = check_over_permissive_iam(snapshot)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_deny_statements_are_ignored(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["iam_policies"][0]["statements"][0]["effect"] = "Deny"
        snapshot["iam_policies"][0]["statements"][0]["actions"] = ["*"]
        snapshot["iam_policies"][0]["statements"][0]["resources"] = ["*"]
        self.assertEqual(check_over_permissive_iam(snapshot), [])

    def test_unencrypted_and_missing_encryption_flags(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["volumes"] = [
            {"id": "vol-a", "encrypted": False},
            {"id": "vol-b"},
        ]
        findings = check_unencrypted_volumes(snapshot)
        self.assertEqual([finding.resource for finding in findings], ["vol-a", "vol-b"])

    def test_missing_logging_reports_three_controls(self):
        findings = check_missing_logging({"logging": {}})
        self.assertEqual([finding.rule_id for finding in findings], [
            "CLOUD-LOG-001",
            "CLOUD-LOG-002",
            "CLOUD-LOG-003",
        ])

    def test_report_counts_and_dict_shape(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["buckets"][0]["public_write"] = True
        snapshot["volumes"][0]["encrypted"] = False
        snapshot["logging"] = {}
        report = evaluate_snapshot(snapshot)
        self.assertEqual(report.counts(), {"low": 0, "medium": 3, "high": 1, "critical": 1})
        payload = report.to_dict()
        self.assertEqual(payload["total"], 5)
        self.assertEqual(set(payload["findings"][0]), {"rule_id", "severity", "resource", "message"})

    def test_findings_sorted_by_severity(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["buckets"][0]["public_write"] = True
        snapshot["volumes"][0]["encrypted"] = False
        snapshot["logging"] = {}
        severities = [finding.severity for finding in evaluate_snapshot(snapshot).findings]
        self.assertEqual(severities, sorted(severities, key=lambda level: -{"low": 0, "medium": 1, "high": 2, "critical": 3}[level]))

    def test_invalid_section_raises_value_error(self):
        with self.assertRaises(ValueError):
            evaluate_snapshot({"buckets": "not-a-list"})

    def test_load_snapshot_rejects_non_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_snapshot(path)

    def test_cli_json_output_and_clean_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(CLEAN), encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["total"], 0)

    def test_cli_fail_on_exit_code(self):
        snapshot = copy.deepcopy(CLEAN)
        snapshot["volumes"][0]["encrypted"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
                code = main([str(path), "--fail-on", "high"])
            self.assertEqual(code, 1)

    def test_cli_missing_file_returns_one(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            code = main(["does-not-exist.json"])
        self.assertEqual(code, 1)
        self.assertIn("error:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
