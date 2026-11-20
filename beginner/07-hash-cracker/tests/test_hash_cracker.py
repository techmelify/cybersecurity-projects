import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hash_cracker import brute_force, dictionary_attack, digest, main  # noqa: E402


class HashCrackerTests(unittest.TestCase):
    def test_digest_algorithms(self):
        self.assertEqual(digest("abc", "md5"), "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(len(digest("abc", "sha256")), 64)
        self.assertEqual(len(digest("abc", "sha512")), 128)

    def test_unsupported_algorithm(self):
        with self.assertRaises(ValueError):
            digest("abc", "md4")

    def test_dictionary_found(self):
        target = digest("letmein", "sha256")
        result = dictionary_attack(target, "sha256", ["password", "letmein", "123456"])
        self.assertTrue(result.found)
        self.assertEqual(result.plaintext, "letmein")
        self.assertEqual(result.attempts, 2)

    def test_dictionary_not_found(self):
        target = digest("missing", "sha256")
        result = dictionary_attack(target, "sha256", ["a", "b"])
        self.assertFalse(result.found)
        self.assertEqual(result.attempts, 2)

    def test_uppercase_target(self):
        target = digest("abc", "sha256").upper()
        self.assertEqual(dictionary_attack(target, "sha256", ["abc"]).plaintext, "abc")

    def test_brute_force_found(self):
        target = digest("ab", "md5")
        result = brute_force(target, "md5", charset="ab", max_length=2)
        self.assertEqual(result.plaintext, "ab")
        self.assertLessEqual(result.attempts, 6)

    def test_brute_force_bad_length(self):
        with self.assertRaises(ValueError):
            brute_force("x", "md5", max_length=0)

    def test_cli_wordlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "words.txt"
            path.write_text("wrong\nsecret\n", encoding="utf-8")
            self.assertEqual(main([digest("secret", "sha256"), "-w", str(path)]), 0)

    def test_cli_brute(self):
        self.assertEqual(main([digest("a", "sha256"), "-b", "1", "--charset", "a"]), 0)

    def test_cli_not_found(self):
        self.assertEqual(main([digest("zzz", "sha256"), "-b", "1", "--charset", "a"]), 1)


if __name__ == "__main__":
    unittest.main()
