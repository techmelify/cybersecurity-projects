import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from canary import CanaryRegistry, InvalidToken, main  # noqa: E402


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "registry.json"
        self.registry = CanaryRegistry.create(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_issue_verify(self):
        token = self.registry.issue("lab doc")
        loaded = CanaryRegistry.load(self.path)
        self.assertIsNotNone(loaded.verify(token.value))

    def test_registry_stores_only_digest(self):
        token = self.registry.issue("secret note")
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn(token.value, raw)
        self.assertIn(token.digest, raw)

    def test_tampered_token(self):
        token = self.registry.issue()
        bad = token.value[:-1] + ("0" if token.value[-1] != "0" else "1")
        self.assertIsNone(CanaryRegistry.load(self.path).verify(bad))

    def test_malformed_token(self):
        with self.assertRaises(InvalidToken):
            self.registry.verify("not-a-token")

    def test_hit_recording(self):
        token = self.registry.issue("tripwire")
        record = self.registry.record_hit(token.value, "192.0.2.10", "lab-browser")
        self.assertEqual(len(record["hits"]), 1)
        self.assertEqual(record["hits"][0]["source"], "192.0.2.10")
        self.assertEqual(CanaryRegistry.load(self.path).list()[0]["hits"], 1)

    def test_unknown_hit(self):
        with self.assertRaises(InvalidToken):
            self.registry.record_hit("ct1_bad.bad")

    def test_cli_flow(self):
        self.assertEqual(main([str(self.path), "issue", "--note", "cli"]), 0)
        self.assertEqual(main([str(self.path), "list"]), 0)


if __name__ == "__main__":
    unittest.main()
