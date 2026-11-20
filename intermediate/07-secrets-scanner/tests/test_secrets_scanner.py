import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secrets_scanner import (  # noqa: E402
    ScanConfig,
    scan_snapshot,
    scan_text,
    shannon_entropy,
    main,
)

AWS = "AKIAZZZZZZZZZZZZZZZZ"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlZm9ydGVzdGluZ3B1cnBvc2Vz"
TOKEN = "aB3dEf7gH9jK2mN4pQ6rS8tU0vW2xY4"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"


class SecretsScannerTests(unittest.TestCase):
    def test_entropy_helper(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)

    def test_detects_aws_access_key(self):
        findings, _ = scan_text(f"key = '{AWS}'")
        self.assertEqual([f.kind for f in findings], ["aws_access_key"])
        self.assertNotIn(AWS, findings[0].masked_value)

    def test_detects_private_key_header(self):
        findings, _ = scan_text(PRIVATE_KEY)
        self.assertEqual(findings[0].kind, "private_key_header")

    def test_detects_jwt(self):
        findings, _ = scan_text(f"Authorization: Bearer {JWT}")
        self.assertEqual([f.kind for f in findings], ["jwt"])

    def test_detects_high_entropy_token(self):
        findings, _ = scan_text(f'api_secret = "{TOKEN}"')
        self.assertEqual([f.kind for f in findings], ["high_entropy_token"])
        self.assertGreaterEqual(findings[0].entropy, 3.5)

    def test_ignores_low_entropy_words(self):
        text = 'password = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"\nword = "aaaaaaaaaaaaaaaaaaaaaaaaaaab"'
        findings, _ = scan_text(text)
        self.assertEqual(findings, ())

    def test_line_suppression(self):
        findings, suppressed = scan_text(f"key = '{AWS}'  # nosec\nother = 1")
        self.assertEqual(findings, ())
        self.assertEqual(suppressed, 1)

    def test_custom_suppression_marker(self):
        config = ScanConfig(suppression_markers=("ALLOW-THIS",))
        findings, suppressed = scan_text(f"key='{AWS}' // ALLOW-THIS", config=config)
        self.assertEqual(findings, ())
        self.assertEqual(suppressed, 1)

    def test_file_level_suppression(self):
        text = f"# secrets-scanner: disable-file\nkey = '{AWS}'\nsecret = '{TOKEN}'"
        findings, suppressed = scan_text(text)
        self.assertEqual(findings, ())
        self.assertEqual(suppressed, 2)

    def test_no_duplicate_findings_for_aws_key(self):
        findings, _ = scan_text(f"AKIA = '{AWS}'")
        self.assertEqual(len(findings), 1)

    def test_snapshot_reports_path_and_line(self):
        result = scan_snapshot({"b.txt": f"ok\nk='{AWS}'", "a.txt": "nothing here"})
        self.assertEqual([f.path for f in result.findings], ["b.txt"])
        self.assertEqual(result.findings[0].line, 2)
        self.assertEqual(result.scanned_files, 2)
        self.assertFalse(result.ok)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text(f"token = {TOKEN}\n", encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 1)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload[0]["kind"], "high_entropy_token")

    def test_cli_clean_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clean.txt"
            path.write_text("nothing_secret here = 1\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(path)])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
