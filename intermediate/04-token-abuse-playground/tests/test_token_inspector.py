import base64
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from token_inspector import (  # noqa: E402
    inspect_token,
    inspection_to_dict,
    main,
    parse_token,
    format_inspection,
)

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)
NOW_TS = NOW.timestamp()
ISSUER = "https://issuer.example.test"


def encode(obj):
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def token(header=None, claims=None, signature="opaque-signature"):
    head = {"alg": "HS256", "typ": "JWT"} if header is None else header
    body = {
        "exp": NOW_TS + 3600,
        "iat": NOW_TS - 3600,
        "aud": "lab-api",
        "iss": ISSUER,
    } if claims is None else claims
    return f"{encode(head)}.{encode(body)}.{signature}"


def codes(inspection):
    return {finding.code for finding in inspection.findings}


def check(*args, **kwargs):
    options = {"now": NOW, "expected_aud": "lab-api", "trusted_issuers": [ISSUER]}
    options.update(kwargs)
    return inspect_token(*args, **options)


class ParseTokenTests(unittest.TestCase):
    def test_parse_valid_token(self):
        parsed = parse_token(token())
        self.assertEqual(parsed.segments, 3)
        self.assertEqual(parsed.header["alg"], "HS256")
        self.assertEqual(parsed.claims["aud"], "lab-api")
        self.assertEqual(parsed.signature, "opaque-signature")

    def test_wrong_segment_count(self):
        with self.assertRaises(ValueError):
            parse_token("only.two")

    def test_non_base64url_segment(self):
        with self.assertRaises(ValueError):
            parse_token("!!!." + encode({}) + ".sig")

    def test_non_json_segment(self):
        broken = base64.urlsafe_b64encode(b"not json").decode().rstrip("=")
        with self.assertRaises(ValueError):
            parse_token(broken + "." + encode({}) + ".sig")

    def test_non_object_segment(self):
        with self.assertRaises(ValueError):
            parse_token(encode([1, 2]) + "." + encode({}) + ".sig")

    def test_non_string_input(self):
        with self.assertRaises(TypeError):
            parse_token(b"bytes")


class InspectTokenTests(unittest.TestCase):
    def test_valid_token_is_allowed(self):
        result = check(token())
        self.assertEqual(result.verdict, "allow")
        self.assertEqual(result.findings, ())

    def test_alg_none_is_critical(self):
        result = check(token(header={"alg": "none"}))
        self.assertIn("alg_none", codes(result))
        self.assertEqual(result.verdict, "reject")
        self.assertEqual(next(f for f in result.findings if f.code == "alg_none").severity, "critical")

    def test_missing_alg(self):
        self.assertIn("alg_missing", codes(check(token(header={"typ": "JWT"}))))

    def test_empty_signature(self):
        self.assertIn("unsigned_token", codes(check(token(signature=""))))

    def test_expired(self):
        result = check(token(claims={"exp": NOW_TS - 10, "iat": NOW_TS - 3600,
                                     "aud": "lab-api", "iss": ISSUER}))
        self.assertIn("expired", codes(result))
        self.assertEqual(result.verdict, "reject")

    def test_missing_exp(self):
        claims = {"iat": NOW_TS - 60, "aud": "lab-api", "iss": ISSUER}
        self.assertIn("exp_missing", codes(check(token(claims=claims))))

    def test_invalid_exp(self):
        claims = {"exp": "tomorrow", "iat": NOW_TS - 60, "aud": "lab-api", "iss": ISSUER}
        self.assertIn("exp_invalid", codes(check(token(claims=claims))))

    def test_iat_in_future(self):
        claims = {"exp": NOW_TS + 7200, "iat": NOW_TS + 3600, "aud": "lab-api", "iss": ISSUER}
        self.assertIn("iat_in_future", codes(check(token(claims=claims))))

    def test_iat_after_exp(self):
        claims = {"exp": NOW_TS + 50, "iat": NOW_TS + 100, "aud": "lab-api", "iss": ISSUER}
        self.assertIn("iat_after_exp", codes(check(token(claims=claims))))

    def test_iat_missing(self):
        claims = {"exp": NOW_TS + 3600, "aud": "lab-api", "iss": ISSUER}
        self.assertIn("iat_missing", codes(check(token(claims=claims))))

    def test_audience_mismatch(self):
        result = check(token(), expected_aud="other-api")
        self.assertIn("aud_mismatch", codes(result))
        self.assertEqual(result.verdict, "reject")

    def test_audience_list_accepts_expected_value(self):
        claims = {"exp": NOW_TS + 3600, "iat": NOW_TS - 60,
                  "aud": ["other-api", "lab-api"], "iss": ISSUER}
        self.assertNotIn("aud_mismatch", codes(check(token(claims=claims))))

    def test_missing_audience_and_issuer(self):
        claims = {"exp": NOW_TS + 3600, "iat": NOW_TS - 60}
        found = codes(check(token(claims=claims)))
        self.assertIn("aud_missing", found)
        self.assertIn("iss_missing", found)

    def test_untrusted_issuer(self):
        claims = {"exp": NOW_TS + 3600, "iat": NOW_TS - 60,
                  "aud": "lab-api", "iss": "https://evil.example.test"}
        self.assertIn("iss_untrusted", codes(check(token(claims=claims))))

    def test_long_lifetime(self):
        claims = {"exp": NOW_TS + 86400, "iat": NOW_TS - 40 * 86400,
                  "aud": "lab-api", "iss": ISSUER}
        self.assertIn("long_lifetime", codes(check(token(claims=claims))))

    def test_missing_time_reference_is_reported(self):
        result = inspect_token(token(), expected_aud="lab-api", trusted_issuers=[ISSUER])
        self.assertIn("time_reference_missing", codes(result))

    def test_report_and_json_shape(self):
        result = check(token(header={"alg": "none"}))
        report = format_inspection(result)
        self.assertIn("Verdict: REJECT", report)
        self.assertIn("alg_none", report)
        payload = inspection_to_dict(result)
        self.assertEqual(payload["verdict"], "reject")
        self.assertEqual(payload["findings"][0]["code"], "alg_none")

    def test_median_findings_give_review_verdict(self):
        claims = {"exp": NOW_TS + 3600, "iat": NOW_TS - 60, "iss": ISSUER}
        result = check(token(claims=claims))
        self.assertIn("aud_missing", codes(result))
        self.assertEqual(result.verdict, "review")


class CliTests(unittest.TestCase):
    def test_cli_token_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main([
                "--token", token(header={"alg": "none"}),
                "--now", NOW.isoformat(),
                "--expect-aud", "lab-api",
                "--trusted-issuer", ISSUER,
                "--json",
            ])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["verdict"], "reject")

    def test_cli_file_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "token.txt"
            path.write_text(token(), encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["--file", str(path), "--now", NOW.isoformat()])
            self.assertEqual(code, 0)
        self.assertIn("Verdict:", buffer.getvalue())

    def test_cli_bad_token(self):
        from contextlib import redirect_stderr

        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--token", "not-a-token"]), 2)


if __name__ == "__main__":
    unittest.main()
