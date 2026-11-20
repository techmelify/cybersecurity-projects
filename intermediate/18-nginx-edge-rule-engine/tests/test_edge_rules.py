import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from edge_rules import Decision, Request, Rule, evaluate, load_request, load_rules, main  # noqa: E402

RULES = [
    Rule("public", "allow", "/public/*", "GET"),
    Rule("admin", "allow", "/api/admin", "POST", "10.0.0.0/8", ("X-Role", "admin")),
    Rule("deny-admin", "deny", "/api/admin"),
    Rule("deny-all", "deny"),
]


class EdgeRuleTests(unittest.TestCase):
    def test_public_prefix_allow(self):
        request = Request("/public/logo", "GET", "203.0.113.5", {})
        self.assertEqual(evaluate(request, RULES), Decision("allow", "public"))

    def test_admin_allow_with_header_and_cidr(self):
        request = Request(
            "/api/admin", "POST", "10.1.2.3", {"x-role": "admin"}
        )
        self.assertTrue(evaluate(request, RULES).allowed)
        self.assertEqual(evaluate(request, RULES).rule, "admin")

    def test_wrong_header_value_falls_through_to_deny(self):
        request = Request(
            "/api/admin", "POST", "10.1.2.3", {"X-Role": "user"}
        )
        self.assertEqual(evaluate(request, RULES).rule, "deny-admin")

    def test_wrong_cidr_falls_through_to_deny(self):
        request = Request(
            "/api/admin", "POST", "192.0.2.5", {"X-Role": "admin"}
        )
        self.assertEqual(evaluate(request, RULES).rule, "deny-admin")

    def test_first_match_wins(self):
        rules = [Rule("allow-all", "allow"), Rule("deny-api", "deny", "/api/*")]
        result = evaluate(Request("/api/x", "GET", "203.0.113.5", {}), rules)
        self.assertEqual(result.rule, "allow-all")

    def test_default_deny(self):
        self.assertEqual(
            evaluate(Request("/x", "GET", "203.0.113.5", {}), []),
            Decision("deny", "default"),
        )

    def test_configurable_default(self):
        result = evaluate(Request("/x", "GET", "203.0.113.5", {}), [], default="allow")
        self.assertTrue(result.allowed)

    def test_load_rules_and_request(self):
        rule_data = [
            {"name": "admin", "action": "ALLOW", "header": ["X-Role", "admin"]}
        ]
        request_data = {
            "path": "/x",
            "method": "post",
            "ip": "192.0.2.1",
            "headers": {"X-Role": "admin"},
        }
        self.assertEqual(load_rules(rule_data)[0].action, "allow")
        self.assertEqual(load_request(request_data).headers, {"X-Role": "admin"})

    def test_cli(self):
        rules = [{"name": "public", "action": "allow", "path": "/public/*"}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps(rules), encoding="utf-8")
            self.assertEqual(
                main([str(path), "--path", "/public/a", "--ip", "203.0.113.5"]), 0
            )
            self.assertEqual(
                main(
                    [
                        str(path), "--path", "/x", "--ip", "203.0.113.5",
                        "--header", "broken",
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
