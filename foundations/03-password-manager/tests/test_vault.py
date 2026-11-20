import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vault import Vault, VaultExists, WrongPassword, create_vault  # noqa: E402


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.json"
        self.vault = create_vault(self.path, "correct horse battery staple")

    def tearDown(self):
        self.tmp.cleanup()

    def test_file_has_no_plaintext(self):
        self.vault.add("mail", "alice", "S3cret!")
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("S3cret!", raw)
        self.assertNotIn("alice", raw)
        self.assertIn("ciphertext", raw)

    def test_unlock_round_trip(self):
        self.vault.add("mail", "alice", "S3cret!")
        unlocked = Vault.unlock(self.path, "correct horse battery staple")
        self.assertEqual(unlocked.get("mail", "alice"), {"alice": "S3cret!"})

    def test_wrong_password(self):
        self.vault.add("mail", "alice", "S3cret!")
        with self.assertRaises(WrongPassword):
            Vault.unlock(self.path, "wrong")

    def test_service_is_case_insensitive(self):
        self.vault.add("GitLab", "alice", "token")
        self.assertEqual(Vault.unlock(self.path, "correct horse battery staple").get("gitlab", "alice"), {"alice": "token"})

    def test_list_services(self):
        self.vault.add("mail", "alice", "one")
        self.vault.add("mail", "bob", "two")
        self.vault.add("vpn", "alice", "three")
        unlocked = Vault.unlock(self.path, "correct horse battery staple")
        self.assertEqual(unlocked.list_services(), {"mail": ["alice", "bob"], "vpn": ["alice"]})

    def test_delete_username(self):
        self.vault.add("mail", "alice", "one")
        self.vault.add("mail", "bob", "two")
        self.vault.delete("mail", "alice")
        self.assertEqual(Vault.unlock(self.path, "correct horse battery staple").get("mail"), {"bob": "two"})

    def test_delete_service(self):
        self.vault.add("mail", "alice", "one")
        self.vault.delete("mail")
        self.assertEqual(Vault.unlock(self.path, "correct horse battery staple").list_services(), {})

    def test_missing_service_raises(self):
        with self.assertRaises(KeyError):
            self.vault.get("nope")

    def test_create_existing_vault(self):
        with self.assertRaises(VaultExists):
            create_vault(self.path, "another password")

    def test_tampered_ciphertext(self):
        self.vault.add("mail", "alice", "one")
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        raw = bytearray(__import__("base64").b64decode(doc["ciphertext"]))
        raw[0] ^= 1
        import base64

        doc["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
        self.path.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaises(WrongPassword):
            Vault.unlock(self.path, "correct horse battery staple")

    def test_unknown_format(self):
        self.path.write_text(json.dumps({"format": "other"}), encoding="utf-8")
        with self.assertRaises(ValueError):
            Vault.unlock(self.path, "correct horse battery staple")

    def test_no_temp_file_left(self):
        self.vault.add("mail", "alice", "one")
        self.assertFalse(self.path.with_suffix(".json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
