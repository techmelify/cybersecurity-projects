import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from route_evaluator import Decision, Request, Route, evaluate, load_routes, main  # noqa: E402


ROUTES = [
    Route("api", "upstream", "app.local", "/api", ("GET", "POST"), {"X-Tenant": "alpha", "X-Flag": "*"}, "backend-a:8080"),
    Route("admin", "deny", "app.local", "/admin", (), {}, ""),
    Route("site", "upstream", "*", "/", (), {}, "backend-b:8080"),
]


class RouteEvaluatorTests(unittest.TestCase):
    def test_host_path_and_upstream(self):
        request = Request("app.local", "/api/users", "GET", {"X-Tenant": "alpha", "X-Flag": "1"})
        self.assertEqual(evaluate(request, ROUTES), Decision("upstream", "api", "backend-a:8080"))
        self.assertTrue(evaluate(request, ROUTES).allowed)

    def test_path_segment_boundary(self):
        request = Request("app.local", "/apixel", "GET", {"X-Tenant": "alpha", "X-Flag": "1"})
        self.assertEqual(evaluate(request, ROUTES).route, "site")
        self.assertEqual(evaluate(Request("app.local", "/api", "GET", {"X-Tenant": "alpha", "X-Flag": "1"}), ROUTES).route, "api")

    def test_method_filter(self):
        request = Request("app.local", "/api/users", "DELETE", {"X-Tenant": "alpha", "X-Flag": "1"})
        self.assertEqual(evaluate(request, ROUTES).route, "site")

    def test_header_requirements(self):
        missing = Request("app.local", "/api", "GET", {"X-Flag": "1"})
        wrong = Request("app.local", "/api", "GET", {"x-tenant": "beta", "X-Flag": "1"})
        self.assertEqual(evaluate(missing, ROUTES).route, "site")
        self.assertEqual(evaluate(wrong, ROUTES).route, "site")

    def test_first_matching_deny(self):
        decision = evaluate(Request("app.local", "/admin/tools", "POST"), ROUTES)
        self.assertEqual(decision, Decision("deny", "admin"))
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.upstream, "")

    def test_default_deny(self):
        self.assertEqual(evaluate(Request("unknown.local", "/x"), []), Decision("deny", "default"))

    def test_host_wildcard_and_case(self):
        request = Request("APP.LOCAL:443", "/anything", "GET")
        self.assertEqual(evaluate(request, ROUTES).route, "site")
        host_only = [Route("h", "upstream", "app.local", "/", (), {}, "up")]
        self.assertEqual(evaluate(request, host_only).route, "h")

    def test_load_routes_wrapper_and_validation(self):
        data = {
            "routes": [
                {
                    "name": "r",
                    "action": "upstream",
                    "host": "app.local",
                    "path": "/api/",
                    "methods": "GET",
                    "headers": {"X-Key": "v"},
                    "upstream": "up:9000",
                }
            ]
        }
        routes = load_routes(data)
        self.assertEqual(routes[0].methods, ("GET",))
        self.assertEqual(routes[0].path, "/api/")
        self.assertEqual(routes[0].upstream, "up:9000")
        with self.assertRaises(ValueError):
            load_routes([{"name": "bad", "action": "redirect"}])

    def test_cli_upstream_and_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "routes.json"
            path.write_text(json.dumps({"routes": [r.__dict__ for r in ROUTES]}), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(
                    [
                        str(path),
                        "--host",
                        "app.local",
                        "--path",
                        "/api",
                        "--method",
                        "GET",
                        "--header",
                        "X-Tenant=alpha",
                        "--header",
                        "X-Flag=anything",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertIn("UPSTREAM backend-a:8080 (api)", out.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([str(path), "--host", "app.local", "--path", "/admin"])
            self.assertEqual(code, 0)
            self.assertIn("DENY (admin)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
