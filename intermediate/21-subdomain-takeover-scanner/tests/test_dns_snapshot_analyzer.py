import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dns_snapshot_analyzer import audit, main, match_provider, normalize_dns, parse_snapshot  # noqa: E402


def ids(findings):
    return [finding.id for finding in findings]


SERVICES = [
    {
        "provider": "Demo Pages",
        "domains": ["pages.test"],
        "note": "Check custom-domain binding.",
    },
    {
        "provider": "Regional Pages",
        "domains": ["eu.pages.test"],
        "note": "Regional binding.",
    },
]


class DnsSnapshotAnalyzerTests(unittest.TestCase):
    def test_normalize_dns(self):
        self.assertEqual(normalize_dns("  Blog.Example.TEST.  "), "blog.example.test")

    def test_parse_snapshot(self):
        snapshot = parse_snapshot(
            {
                "cname_records": [{"host": "blog.example.test", "target": "u.pages.test."}],
                "known_services": SERVICES,
                "dangling_targets": ["gone.hosting.test"],
            }
        )
        self.assertEqual(snapshot.records[0].target, "u.pages.test")
        self.assertEqual(snapshot.services[0].provider, "Demo Pages")
        self.assertEqual(snapshot.dangling_targets, ("gone.hosting.test",))

    def test_match_provider_prefers_longest_suffix(self):
        services = parse_snapshot({"known_services": SERVICES}).services
        service = match_provider("tenant.eu.pages.test", services)
        self.assertEqual(service.provider, "Regional Pages")
        self.assertIsNone(match_provider("unrelated.example.test", services))

    def test_dangling_cname_is_flagged(self):
        findings = audit(
            parse_snapshot(
                {
                    "cname_records": [{"host": "old.example.test", "target": "gone.hosting.test"}],
                    "dangling_targets": ["gone.hosting.test"],
                }
            )
        )
        self.assertEqual(ids(findings), ["DNS-001"])
        self.assertIn("dangling", findings[0].detail)

    def test_provider_and_bare_apex_findings(self):
        findings = audit(
            parse_snapshot(
                {
                    "cname_records": [
                        {"host": "a.example.test", "target": "tenant.pages.test"},
                        {"host": "b.example.test", "target": "pages.test"},
                    ],
                    "known_services": SERVICES,
                }
            )
        )
        self.assertEqual(
            [(finding.id, finding.host) for finding in findings],
            [("DNS-002", "a.example.test"), ("DNS-002", "b.example.test"), ("DNS-003", "b.example.test")],
        )

    def test_clean_snapshot_has_no_findings(self):
        findings = audit(
            parse_snapshot(
                {
                    "cname_records": [
                        {"host": "app.example.test", "target": "static.controlled.test"}
                    ],
                    "known_services": SERVICES,
                    "dangling_targets": [],
                }
            )
        )
        self.assertEqual(findings, [])

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(
                json.dumps(
                    {
                        "cname_records": [
                            {"host": "old.example.test", "target": "gone.hosting.test"}
                        ],
                        "dangling_targets": ["gone.hosting.test"],
                    }
                ),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual([item["id"] for item in payload], ["DNS-001"])


if __name__ == "__main__":
    unittest.main()
