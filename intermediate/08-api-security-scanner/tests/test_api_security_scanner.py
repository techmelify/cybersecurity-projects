import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api_security_scanner import analyze_spec, main  # noqa: E402


BEARER = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}


def spec(schemes=None, security=None, paths=None):
    document = {
        "openapi": "3.0.3",
        "info": {"title": "Synthetic API", "version": "1.0"},
        "paths": paths
        if paths is not None
        else {
            "/widgets": {
                "get": {
                    "summary": "List widgets",
                    "responses": {"200": {"description": "ok"}, "429": {"description": "rate limited"}},
                }
            }
        },
    }
    if schemes is not None:
        document["components"] = {"securitySchemes": schemes}
    if security is not None:
        document["security"] = security
    return document


class ApiSecurityScannerTests(unittest.TestCase):
    def test_missing_security_schemes(self):
        report = analyze_spec(spec())
        self.assertIn("SEC001", [f.rule for f in report.findings])

    def test_clean_spec_has_no_findings(self):
        document = spec(
            schemes={"bearerAuth": BEARER},
            security=[{"bearerAuth": []}],
        )
        report = analyze_spec(document)
        self.assertEqual(report.findings, ())
        self.assertTrue(report.ok)
        self.assertEqual(report.operations_scanned, 1)

    def test_weak_basic_auth(self):
        document = spec(
            schemes={"oldAuth": {"type": "http", "scheme": "basic"}},
            security=[{"oldAuth": []}],
        )
        finding = next(f for f in analyze_spec(document).findings if f.rule == "SEC003")
        self.assertIn("basic", finding.message)

    def test_api_key_in_query_is_weak(self):
        document = spec(
            schemes={"key": {"type": "apiKey", "in": "query", "name": "key"}},
            security=[{"key": []}],
        )
        self.assertIn("query string", analyze_spec(document).findings[0].message)

    def test_oauth_implicit_is_weak(self):
        document = spec(
            schemes={"oauth": {"type": "oauth2", "flows": {"implicit": {"authorizationUrl": "https://example.invalid/auth"}}}},
            security=[{"oauth": []}],
        )
        self.assertIn("implicit", analyze_spec(document).findings[0].message)

    def test_undefined_scheme_reference(self):
        document = spec(schemes={"bearerAuth": BEARER}, security=[{"missingAuth": []}])
        rules = [f.rule for f in analyze_spec(document).findings]
        self.assertIn("SEC002", rules)

    def test_unauthenticated_write_is_flagged(self):
        paths = {
            "/widgets": {
                "post": {
                    "security": [],
                    "responses": {"201": {"description": "created"}, "429": {"description": "rate limited"}},
                }
            }
        }
        document = spec(schemes={"bearerAuth": BEARER}, paths=paths)
        report = analyze_spec(document)
        self.assertIn("SEC005", [f.rule for f in report.findings])

    def test_global_security_covers_write(self):
        paths = {
            "/widgets": {
                "post": {"responses": {"201": {"description": "created"}, "429": {"description": "rate limited"}}}
            }
        }
        document = spec(schemes={"bearerAuth": BEARER}, security=[{"bearerAuth": []}], paths=paths)
        self.assertNotIn("SEC005", [f.rule for f in analyze_spec(document).findings])

    def test_missing_rate_limit_description(self):
        paths = {"/things": {"get": {"responses": {"200": {"description": "ok"}}}}}
        document = spec(schemes={"bearerAuth": BEARER}, security=[{"bearerAuth": []}], paths=paths)
        self.assertIn("SEC006", [f.rule for f in analyze_spec(document).findings])

    def test_verbose_error_response(self):
        paths = {
            "/things": {
                "get": {
                    "responses": {
                        "200": {"description": "ok"},
                        "429": {"description": "rate limited"},
                        "500": {
                            "description": "failure",
                            "content": {"application/json": {"example": {"detail": "Traceback (most recent call last): line 9"}}},
                        },
                    }
                }
            }
        }
        document = spec(schemes={"bearerAuth": BEARER}, security=[{"bearerAuth": []}], paths=paths)
        finding = next(f for f in analyze_spec(document).findings if f.rule == "SEC004")
        self.assertIn("500", finding.message)

    def test_severity_filter(self):
        report = analyze_spec(spec())
        self.assertTrue(report.at_or_above("high"))
        self.assertTrue(all(f.severity == "low" for f in report.at_or_above("low") if f.rule == "SEC006"))

    def test_invalid_spec_shape(self):
        with self.assertRaises(ValueError):
            analyze_spec({"paths": []})
        with self.assertRaises(TypeError):
            analyze_spec([])

    def test_cli_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.json"
            path.write_text(json.dumps(spec()), encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json", "--strict"])
            self.assertEqual(code, 1)
            self.assertTrue(json.loads(buffer.getvalue()))

    def test_cli_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "spec.json"
            clean = spec(schemes={"bearerAuth": BEARER}, security=[{"bearerAuth": []}])
            path.write_text(json.dumps(clean), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(path)])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
