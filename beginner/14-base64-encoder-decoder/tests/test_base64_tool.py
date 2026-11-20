import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from base64_tool import CodecError, decode_file, decode_text, encode_file, encode_text, main  # noqa: E402


class Base64Tests(unittest.TestCase):
    def test_text_round_trip(self):
        self.assertEqual(decode_text(encode_text("hello world").value), "hello world")

    def test_unicode(self):
        self.assertEqual(decode_text(encode_text("café ☕").value), "café ☕")

    def test_urlsafe(self):
        data = bytes(range(256))
        encoded = encode_file(Path(__file__), urlsafe=False)  # sanity: works on a real file
        self.assertNotIn("\n", encoded)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.bin"
            path.write_bytes(data)
            value = encode_file(path, urlsafe=True)
            self.assertNotIn("+", value)
            self.assertNotIn("/", value)
            out = Path(tmp) / "out.bin"
            self.assertEqual(decode_file(value, out, urlsafe=True), 256)
            self.assertEqual(out.read_bytes(), data)

    def test_reject_invalid(self):
        with self.assertRaises(CodecError):
            decode_text("not!base64")

    def test_reject_non_utf8(self):
        import base64

        with self.assertRaises(CodecError):
            decode_text(base64.b64encode(b"\xff\xfe").decode())

    def test_cli(self):
        self.assertEqual(main(["encode", "abc"]), 0)
        self.assertEqual(main(["decode", "YWJj"]), 0)
        self.assertEqual(main(["--urlsafe", "encode", "abc"]), 0)


if __name__ == "__main__":
    unittest.main()
