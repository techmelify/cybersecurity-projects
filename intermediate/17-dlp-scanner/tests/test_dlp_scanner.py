import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dlp_scanner import Finding, luhn_valid, main, redact, scan_text  # noqa: E402


class DlpScannerTests(unittest.TestCase):
    def test_email_detected(self):
        findings = scan_text("mail user@example.test now", "note")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "email")
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].source, "note")

    def test_national_id_detected(self):
        findings = scan_text("id 123-45-6789")
        self.assertEqual(findings[0].kind, "national-id-like")
        self.assertEqual(findings[0].severity, "high")

    def test_valid_card_detected(self):
        findings = scan_text("card 4111 1111 1111 1111")
        cards = [f for f in findings if f.kind == "credit-card-like"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0].severity, "high")

    def test_invalid_card_ignored(self):
        findings = scan_text("card 4111 1111 1111 1112")
        self.assertFalse(any(f.kind == "credit-card-like" for f in findings))

    def test_api_key_detected(self):
        key = "AKIA" + "A" * 16
        findings = scan_text(f"token {key}")
        self.assertEqual(findings[0].kind, "api-key")
        self.assertEqual(findings[0].severity, "high")

    def test_clean_text(self):
        self.assertEqual(scan_text("nothing sensitive here"), [])

    def test_luhn_valid(self):
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertTrue(luhn_valid("4111 1111 1111 1111"))
        self.assertFalse(luhn_valid("4111111111111112"))
        self.assertFalse(luhn_valid("123"))

    def test_redact(self):
        self.assertEqual(redact("abcdefgh"), "ab****gh")
        self.assertEqual(redact("abcd"), "****")
        self.assertNotIn("secret", redact("my-secret-value"))

    def test_multiple_findings_are_ordered(self):
        text = "user@example.test and 123-45-6789"
        findings = scan_text(text)
        self.assertEqual([f.kind for f in findings], ["email", "national-id-like"])
        self.assertLess(findings[0].start, findings[1].start)

    def test_finding_is_immutable(self):
        finding = Finding("src", "email", "low", "a@b.test", "a@b.test", 0)
        with self.assertRaises(Exception):
            finding.severity = "high"  # type: ignore[misc]

    def test_cli_prints_redacted_only(self):
        snapshots = {
            "note.txt": "mail user@example.test and id 123-45-6789",
            "clean.txt": "nothing here",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshots.json"
            path.write_text(json.dumps(snapshots), encoding="utf-8")
            self.assertEqual(main([str(path)]), 0)
            path.write_text("[]", encoding="utf-8")
            self.assertEqual(main([str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
