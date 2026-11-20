import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector import main, scan_domain, scan_qr_payload  # noqa: E402


class DetectorTests(unittest.TestCase):
    def test_clean_domain(self):
        result = scan_domain("example.com")
        self.assertEqual(result.score, 0)
        self.assertFalse(result.suspicious)

    def test_homoglyph(self):
        result = scan_domain("exаmple.com")  # Cyrillic 'a'
        self.assertTrue(result.suspicious)
        self.assertEqual(result.normalized, "example.com")

    def test_typo(self):
        result = scan_domain("examp1e.com")
        self.assertTrue(result.suspicious)
        self.assertTrue(any("edit distance" in r for r in result.reasons))

    def test_hyphens(self):
        result = scan_domain("ex-am-ple.com")
        self.assertTrue(result.suspicious)

    def test_custom_brand(self):
        result = scan_domain("acme-secure.com", ("acme",))
        self.assertGreaterEqual(result.score, 2)

    def test_qr_shortener(self):
        result = scan_qr_payload("https://bit.ly/abc")
        self.assertTrue(result.suspicious)
        self.assertTrue(any("shortener" in r for r in result.reasons))

    def test_qr_plain_http_login(self):
        result = scan_qr_payload("http://192.0.2.10/verify")
        self.assertGreaterEqual(result.score, 3)

    def test_qr_clean_https(self):
        result = scan_qr_payload("https://example.com/docs")
        self.assertEqual(result.score, 0)

    def test_cli(self):
        self.assertEqual(main(["domain", "example.com"]), 0)
        self.assertEqual(main(["qr", "https://example.com"]), 0)


if __name__ == "__main__":
    unittest.main()
