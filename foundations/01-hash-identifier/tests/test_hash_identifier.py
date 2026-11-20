import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hash_identifier import format_report, identify, main  # noqa: E402


class IdentifyTests(unittest.TestCase):
    def test_sha256(self):
        result = identify("a" * 64)
        self.assertEqual([m.name for m in result], ["SHA-256"])
        self.assertEqual(result[0].confidence, "high")

    def test_md5_is_ambiguous(self):
        result = identify("d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(result[0].name, "MD5 / NTLM / LM")
        self.assertEqual(result[0].confidence, "medium")

    def test_sha1_sha384_sha512(self):
        for length, name in ((40, "SHA-1"), (96, "SHA-384"), (128, "SHA-512")):
            with self.subTest(length=length):
                self.assertEqual(identify("0" * length)[0].name, name)

    def test_bcrypt_variants(self):
        for prefix in ("2a", "2b", "2y"):
            value = "$" + prefix + "$10$" + "." * 53
            self.assertEqual(identify(value)[0].name, "bcrypt")
        self.assertEqual(identify("$2b$10$" + "." * 52)[0].name, "Malformed bcrypt")

    def test_argon2id_phc(self):
        value = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$YWJjZA"
        result = identify(value)
        self.assertEqual(result[0].name, "Argon2id")
        self.assertEqual(result[0].confidence, "high")

    def test_unknown_phc(self):
        result = identify("$madeup$v=1$abc$def")
        self.assertEqual(result[0].name, "PHC string (madeup)")
        self.assertEqual(result[0].confidence, "medium")

    def test_odd_hex_length(self):
        result = identify("abc")
        self.assertEqual(result[0].name, "Unknown hex string")
        self.assertEqual(result[0].confidence, "low")

    def test_non_hex(self):
        result = identify("not a hash")
        self.assertEqual(result[0].name, "Unknown format")

    def test_empty_and_whitespace(self):
        self.assertEqual(identify(""), [])
        self.assertEqual(identify("   "), [])

    def test_whitespace_is_stripped(self):
        self.assertEqual(identify("  " + "a" * 64 + "  ")[0].name, "SHA-256")

    def test_format_report_truncates_long_input(self):
        report = format_report("a" * 128, identify("a" * 128))
        self.assertIn("...", report.splitlines()[0])
        self.assertIn("SHA-512", report)

    def test_main_with_string(self):
        self.assertEqual(main(["a" * 64]), 0)

    def test_main_with_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hashes.txt"
            path.write_text("a" * 40 + "\n\n" + "b" * 32 + "\n", encoding="utf-8")
            self.assertEqual(main(["--file", str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
