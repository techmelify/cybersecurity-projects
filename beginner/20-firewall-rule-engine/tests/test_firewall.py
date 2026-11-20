import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall import Decision, Packet, Rule, evaluate, load_rules, main  # noqa: E402


RULES = [
    Rule("web", "allow", "0.0.0.0/0", "10.0.0.0/8", "80,443", "tcp"),
    Rule("admin", "allow", "192.168.1.0/24", "10.0.0.0/8", "22", "tcp"),
    Rule("block", "deny", "0.0.0.0/0", "0.0.0.0/0", "1-65535", "any"),
]


class FirewallTests(unittest.TestCase):
    def test_allow_web(self):
        result = evaluate(Packet("8.8.8.8", "10.1.2.3", 443), RULES)
        self.assertTrue(result.allowed)
        self.assertEqual(result.rule, "web")

    def test_deny_unlisted(self):
        result = evaluate(Packet("8.8.8.8", "10.1.2.3", 3389), RULES)
        self.assertFalse(result.allowed)
        self.assertEqual(result.rule, "block")

    def test_source_cidr(self):
        result = evaluate(Packet("192.168.1.5", "10.0.0.1", 22), RULES)
        self.assertEqual(result.rule, "admin")
        result = evaluate(Packet("192.168.2.5", "10.0.0.1", 22), RULES)
        self.assertEqual(result.rule, "block")

    def test_default_deny(self):
        self.assertEqual(evaluate(Packet("1.1.1.1", "2.2.2.2", 80), []), Decision("deny", "default"))

    def test_protocol(self):
        result = evaluate(Packet("8.8.8.8", "10.1.2.3", 80, "udp"), RULES)
        self.assertEqual(result.rule, "block")

    def test_load_rules(self):
        data = [{"name": "x", "action": "allow", "port": "443"}]
        self.assertEqual(load_rules(data)[0].port, "443")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps([{"name": "x", "action": "allow", "port": "80"}]), encoding="utf-8")
            self.assertEqual(main([str(path), "--src", "1.1.1.1", "--dst", "2.2.2.2", "--port", "80"]), 0)


if __name__ == "__main__":
    unittest.main()
