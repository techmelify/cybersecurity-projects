import base64
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from obfuscation_detector import (  # noqa: E402
    analyze_text,
    format_report,
    level_for_score,
    main,
)

PLAIN = "The quick brown fox jumps over the lazy dog. Layered defenses improve security scores."
SAMPLE = b"safe synthetic fixture text for detector tests"


def kinds(detection):
    return {indicator.kind for indicator in detection.indicators}


class AnalyzeTextTests(unittest.TestCase):
    def test_plain_text_is_clean(self):
        result = analyze_text(PLAIN)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.level, "low")
        self.assertEqual(result.indicators, ())
        self.assertEqual(result.layers, 0)

    def test_base64_run(self):
        text = "value=" + base64.b64encode(SAMPLE).decode()
        result = analyze_text(text)
        self.assertIn("base64", kinds(result))
        self.assertNotIn("hex", kinds(result))
        self.assertEqual(result.layers, 1)
        self.assertEqual(result.score, 20)
        self.assertEqual(result.level, "medium")
        self.assertNotIn(SAMPLE.decode(), format_report(result))

    def test_hex_run(self):
        text = "blob=" + SAMPLE.hex()
        result = analyze_text(text)
        self.assertIn("hex", kinds(result))
        self.assertEqual(result.layers, 1)

    def test_base64_and_hex_are_layered(self):
        text = base64.b64encode(SAMPLE).decode() + " " + SAMPLE.hex()
        result = analyze_text(text)
        self.assertIn("layered_encoding", kinds(result))
        self.assertEqual(result.layers, 2)
        self.assertEqual(result.score, 55)

    def test_short_base64_is_ignored(self):
        result = analyze_text("value=QUJDRA==")
        self.assertEqual(result.score, 0)

    def test_non_printable_decoded_base64_is_ignored(self):
        token = base64.b64encode(bytes(range(32))).decode()
        self.assertEqual(analyze_text("x " + token).score, 0)

    def test_hex_escape_runs(self):
        result = analyze_text(r"\x41" * 12)
        self.assertIn("hex_escapes", kinds(result))
        self.assertIn("escaped_string", kinds(result))
        self.assertGreaterEqual(result.layers, 2)

    def test_unicode_escape_runs(self):
        result = analyze_text(r"\u0041" * 14)
        self.assertIn("unicode_escapes", kinds(result))
        self.assertIn("escaped_string", kinds(result))
        self.assertIn("layered_encoding", kinds(result))

    def test_long_escaped_string(self):
        result = analyze_text("text = " + r"\n\t\r" * 6)
        self.assertIn("escaped_string", kinds(result))

    def test_doubled_backslashes(self):
        result = analyze_text(("segment " + r"\\" * 2) * 5)
        self.assertIn("double_escape", kinds(result))

    def test_xor_literal(self):
        result = analyze_text("mask = 0x41 ^ 0x2a")
        self.assertIn("xor_literal", kinds(result))
        self.assertEqual(result.score, 20)

    def test_xor_keyword_with_context(self):
        result = analyze_text("xor_key = 0x41; decode the synthetic value")
        self.assertIn("xor_keyword", kinds(result))

    def test_xor_word_without_context_is_ignored(self):
        result = analyze_text("The lesson covers XOR arithmetic.")
        self.assertEqual(result.score, 0)

    def test_char_codes(self):
        result = analyze_text("chr(65) + chr(66) + chr(67)")
        self.assertIn("char_codes", kinds(result))

    def test_score_is_capped(self):
        text = " ".join([
            base64.b64encode(SAMPLE).decode(),
            SAMPLE.hex(),
            r"\x41" * 12,
            r"\u0041" * 8,
            ("segment " + r"\\" * 2) * 5,
            "mask = 0x41 ^ 0x2a",
            "xor_key = 0x41; decode",
            "chr(65) + chr(66) + chr(67)",
        ])
        result = analyze_text(text)
        self.assertEqual(result.score, 100)
        self.assertEqual(result.level, "critical")

    def test_indicator_offsets_and_report(self):
        result = analyze_text("prefix " + base64.b64encode(SAMPLE).decode())
        self.assertTrue(all(indicator.offset >= 0 for indicator in result.indicators))
        report = format_report(result)
        self.assertIn("base64", report)
        self.assertIn("Encoding layers: 1", report)
        self.assertIn("Indicators: none", format_report(analyze_text(PLAIN)))

    def test_level_thresholds(self):
        self.assertEqual(level_for_score(0), "low")
        self.assertEqual(level_for_score(19), "low")
        self.assertEqual(level_for_score(20), "medium")
        self.assertEqual(level_for_score(50), "high")
        self.assertEqual(level_for_score(100), "critical")

    def test_non_string_input(self):
        with self.assertRaises(TypeError):
            analyze_text(b"bytes")


class CliTests(unittest.TestCase):
    def test_cli_text_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--text", "mask = 0x41 ^ 0x2a", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["score"], 20)

    def test_cli_file_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text(base64.b64encode(SAMPLE).decode(), encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["--file", str(path)])
            self.assertEqual(code, 0)
        self.assertIn("Score:", buffer.getvalue())

    def test_cli_missing_file(self):
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--file", str(Path(tmp) / "nope.txt")]), 2)


if __name__ == "__main__":
    unittest.main()
