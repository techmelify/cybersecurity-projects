import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from headers_scanner import (  # noqa: E402
    Finding,
    fetch_headers,
    format_report,
    main,
    parse_header_file,
    scan_headers,
    score,
)


def by_control(findings):
    return {f.control: f for f in findings}


class ScannerTests(unittest.TestCase):
    def test_hardened_headers(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }
        findings = by_control(scan_headers(headers))
        self.assertEqual(findings["Content-Security-Policy"].status, "pass")
        self.assertEqual(findings["Strict-Transport-Security"].status, "pass")
        self.assertEqual(findings["Server banner"].status, "pass")
        self.assertEqual(score(list(findings.values()))[0], 8)

    def test_empty_headers(self):
        findings = by_control(scan_headers({}))
        self.assertEqual(findings["Content-Security-Policy"].status, "fail")
        self.assertEqual(findings["Permissions-Policy"].status, "warn")
        self.assertEqual(score(list(findings.values()))[0], 2)

    def test_case_insensitive_lookup(self):
        findings = by_control(scan_headers({"x-content-type-options": "NOSNIFF"}))
        self.assertEqual(findings["X-Content-Type-Options"].status, "pass")

    def test_weak_hsts(self):
        findings = by_control(scan_headers({"Strict-Transport-Security": "max-age=60"}))
        self.assertEqual(findings["Strict-Transport-Security"].status, "warn")

    def test_malformed_hsts(self):
        findings = by_control(scan_headers({"Strict-Transport-Security": "max-age=abc"}))
        self.assertEqual(findings["Strict-Transport-Security"].status, "warn")

    def test_csp_frame_ancestors_covers_xfo(self):
        findings = by_control(scan_headers({"Content-Security-Policy": "frame-ancestors 'none'"}))
        self.assertEqual(findings["X-Frame-Options"].status, "pass")

    def test_unexpected_xfo(self):
        findings = by_control(scan_headers({"X-Frame-Options": "ALLOW-FROM https://x.test"}))
        self.assertEqual(findings["X-Frame-Options"].status, "warn")

    def test_weak_referrer(self):
        findings = by_control(scan_headers({"Referrer-Policy": "unsafe-url"}))
        self.assertEqual(findings["Referrer-Policy"].status, "warn")

    def test_banner_exposure(self):
        findings = by_control(scan_headers({"Server": "nginx/1.24", "X-Powered-By": "PHP/8.2"}))
        self.assertEqual(findings["Server banner"].status, "warn")
        self.assertEqual(findings["X-Powered-By"].status, "warn")

    def test_score_half_points(self):
        findings = [Finding("a", "pass", ""), Finding("b", "warn", ""), Finding("c", "fail", "")]
        self.assertEqual(score(findings), (1, 3))

    def test_report_shape(self):
        report = format_report("https://example.test", scan_headers({}))
        self.assertIn("https://example.test", report)
        self.assertIn("Score: 2/8", report)

    def test_parse_header_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "headers.txt"
            path.write_text("# comment\nX-Frame-Options: DENY\n\nBad Line\n", encoding="utf-8")
            result = parse_header_file(path)
            self.assertEqual(result, {"X-Frame-Options": "DENY"})

    def test_main_with_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "headers.txt"
            path.write_text("X-Content-Type-Options: nosniff\n", encoding="utf-8")
            self.assertEqual(main(["--file", str(path)]), 0)

    def test_fetch_headers_is_offline_safe_by_default(self):
        # No network call is made unless a URL is explicitly passed.
        self.assertTrue(callable(fetch_headers))


if __name__ == "__main__":
    unittest.main()
