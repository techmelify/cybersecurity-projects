import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fingerprint import (  # noqa: E402
    ClientHello,
    ja3_hash,
    ja3_string,
    ja4_like_hash,
    fingerprint,
    load_hellos,
    main,
)

HELLO = ClientHello(
    version=771,
    ciphers=(1, 2, 3),
    extensions=(10, 11),
    curves=(23,),
    formats=(0,),
)


class FingerprintTests(unittest.TestCase):
    def test_ja3_string(self):
        self.assertEqual(ja3_string(HELLO), "771,1-2-3,10-11,23,0")

    def test_ja3_string_with_empty_lists(self):
        hello = ClientHello(version=771)
        self.assertEqual(ja3_string(hello), "771,,,,")

    def test_ja3_hash_matches_md5_of_canonical_string(self):
        expected = hashlib.md5(b"771,1-2-3,10-11,23,0").hexdigest()
        self.assertEqual(ja3_hash(HELLO), expected)
        self.assertEqual(len(ja3_hash(HELLO)), 32)

    def test_ja3_is_order_sensitive(self):
        reordered = ClientHello(771, (3, 2, 1), (10, 11), (23,), (0,))
        self.assertNotEqual(ja3_hash(HELLO), ja3_hash(reordered))

    def test_ja4_like_is_order_insensitive(self):
        reordered = ClientHello(771, (3, 1, 2), (11, 10), (23,), (0,))
        self.assertEqual(ja4_like_hash(HELLO), ja4_like_hash(reordered))

    def test_ja4_like_reacts_to_new_extension(self):
        extended = ClientHello(771, (1, 2, 3), (10, 11, 12), (23,), (0,))
        self.assertNotEqual(ja4_like_hash(HELLO), ja4_like_hash(extended))
        self.assertEqual(len(ja4_like_hash(HELLO)), 16)

    def test_fingerprint_bundle(self):
        result = fingerprint(HELLO)
        self.assertEqual(result.ja3, ja3_hash(HELLO))
        self.assertEqual(result.ja4_like, ja4_like_hash(HELLO))
        self.assertEqual(result.ja3_string, "771,1-2-3,10-11,23,0")

    def test_load_hellos(self):
        data = [{"version": "771", "ciphers": [1, 2], "extensions": [10]}]
        self.assertEqual(
            load_hellos(data), [ClientHello(771, (1, 2), (10,), (), ())]
        )

    def test_cli(self):
        data = [{"version": 771, "ciphers": [1, 2], "extensions": [10]}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hellos.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(main([str(path)]), 0)
            self.assertEqual(main([str(path), "--algo", "ja3"]), 0)
            self.assertEqual(main([str(path), "--algo", "ja4"]), 0)
            with self.assertRaises(SystemExit):
                main([str(path), "--algo", "bogus"])


if __name__ == "__main__":
    unittest.main()
