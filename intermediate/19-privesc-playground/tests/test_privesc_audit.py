import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from privesc_audit import audit, main, parse_mode, parse_snapshot, summarize  # noqa: E402


def ids(findings):
    return [finding.id for finding in findings]


class PrivescAuditTests(unittest.TestCase):
    def test_parse_mode_accepts_octal_forms(self):
        self.assertEqual(parse_mode("4755"), 0o4755)
        self.assertEqual(parse_mode(4755), 0o4755)
        with self.assertRaises(ValueError):
            parse_mode("4895")

    def test_clean_snapshot_has_no_findings(self):
        findings = audit(
            parse_snapshot(
                {
                    "suid_files": [{"path": "/usr/bin/safe", "owner": "root", "mode": "4750"}],
                    "sudoers_lines": ["Defaults env_reset", "alice ALL=(ops) /usr/bin/true"],
                    "world_writable_dirs": [{"path": "/tmp", "mode": "1777"}],
                }
            )
        )
        self.assertEqual(findings, [])

    def test_risky_suid_and_directory_findings(self):
        findings = audit(
            parse_snapshot(
                {
                    "suid_files": [
                        {"path": "/opt/a", "owner": "root", "mode": "4777"},
                        {"path": "/opt/b", "owner": "svc", "mode": "4755"},
                    ],
                    "world_writable_dirs": [{"path": "/var/tmp/shared", "mode": "0777"}],
                }
            )
        )
        self.assertEqual(
            ids(findings),
            ["DIR-001", "SUID-001", "SUID-002", "SUID-003"],
        )

    def test_sudoers_patterns(self):
        findings = audit(
            parse_snapshot(
                {
                    "sudoers_lines": [
                        "alice ALL=(ALL) NOPASSWD: ALL",
                        "bob ALL=(ALL) ALL",
                        "carol ALL=(ALL) /opt/tools/*",
                        "Defaults !env_reset",
                    ]
                }
            )
        )
        self.assertEqual(ids(findings), ["SUDO-001", "SUDO-002", "SUDO-003", "SUDO-004"])

    def test_writable_directory_containing_setuid_path(self):
        findings = audit(
            parse_snapshot(
                {
                    "suid_files": [{"path": "/opt/team/helper", "owner": "root", "mode": "4755"}],
                    "world_writable_dirs": [{"path": "/opt/team", "mode": "1777"}],
                }
            )
        )
        self.assertIn("DIR-002", ids(findings))
        self.assertNotIn("DIR-001", ids(findings))

    def test_summarize_counts(self):
        findings = audit(
            parse_snapshot(
                {
                    "suid_files": [{"path": "/opt/a", "owner": "root", "mode": "4777"}],
                    "sudoers_lines": ["Defaults !env_reset"],
                }
            )
        )
        self.assertEqual(summarize(findings), {"low": 1, "medium": 0, "high": 2})

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(
                json.dumps({"sudoers_lines": ["alice ALL=(ALL) NOPASSWD: ALL"]}),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual([item["id"] for item in payload], ["SUDO-001", "SUDO-004"])


if __name__ == "__main__":
    unittest.main()
