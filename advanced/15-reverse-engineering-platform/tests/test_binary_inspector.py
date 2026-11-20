import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from binary_inspector import (  # noqa: E402
    InspectionReport,
    inspect_blob,
    main,
    parse_hex,
)


def make_elf() -> bytes:
    blob = bytearray(0x40 + 64)
    blob[0:4] = b"\x7fELF"
    blob[4] = 2  # ELF64
    blob[5] = 1  # little endian
    blob[18:20] = (0x3E).to_bytes(2, "little")  # x86-64
    blob[0x28:0x30] = (0x40).to_bytes(8, "little")  # section table offset
    blob[0x3A:0x3C] = (64).to_bytes(2, "little")  # entry size
    blob[0x3C:0x3E] = (1).to_bytes(2, "little")  # one section
    blob[0x40 + 32 : 0x40 + 40] = (256).to_bytes(8, "little")
    return bytes(blob)


def make_pe() -> bytes:
    pe = 0x80
    table = pe + 24 + 0xF0
    blob = bytearray(table + 40)
    blob[0:2] = b"MZ"
    blob[0x3C:0x40] = pe.to_bytes(4, "little")
    blob[pe : pe + 4] = b"PE\0\0"
    blob[pe + 4 : pe + 6] = (0x8664).to_bytes(2, "little")
    blob[pe + 6 : pe + 8] = (1).to_bytes(2, "little")
    blob[pe + 20 : pe + 22] = (0xF0).to_bytes(2, "little")
    blob[table : table + 8] = b".text\0\0\0"
    blob[table + 16 : table + 20] = (0x100).to_bytes(4, "little")
    return bytes(blob)


class BinaryInspectorTests(unittest.TestCase):
    def test_elf_header(self):
        report = inspect_blob(make_elf())
        self.assertEqual(report.header.format, "ELF")
        self.assertIn("x86-64", report.header.architecture)
        self.assertEqual(report.header.magic, "7f454c46")
        self.assertEqual(report.header.sections[0].size, 256)

    def test_pe_header(self):
        report = inspect_blob(make_pe())
        self.assertEqual(report.header.format, "PE")
        self.assertIn("x86-64", report.header.architecture)
        self.assertEqual(report.header.sections[0].name, ".text")
        self.assertEqual(report.header.sections[0].size, 0x100)

    def test_unknown_header(self):
        report = inspect_blob(b"just text, not a binary")
        self.assertEqual(report.header.format, "unknown")
        self.assertEqual(report.header.sections, ())

    def test_printable_strings(self):
        report = inspect_blob(b"\x00\x01hello world\x00ABC\x00", min_string_length=4)
        self.assertEqual([(item.offset, item.value) for item in report.strings], [(2, "hello world")])

    def test_imports(self):
        report = inspect_blob(b"kernel32.dll\0libcrypto.so.3\0hello\0")
        names = {item.library for item in report.imports}
        self.assertIn("kernel32.dll", names)
        self.assertIn("libcrypto.so", names)

    def test_entropy(self):
        self.assertEqual(inspect_blob(b"\x00" * 256).entropy, 0.0)
        self.assertEqual(inspect_blob(bytes(range(256))).entropy, 8.0)
        self.assertEqual(inspect_blob(b"").entropy, 0.0)

    def test_string_and_import_caps(self):
        blob = b"\x00".join(f"string{n:03d}".encode() for n in range(300))
        report = inspect_blob(blob, max_strings=5, max_imports=0)
        self.assertEqual(len(report.strings), 5)
        self.assertEqual(report.imports, ())

    def test_empty_blob_and_determinism(self):
        report = inspect_blob(b"")
        self.assertIsInstance(report, InspectionReport)
        self.assertEqual(report.size, 0)
        self.assertEqual(report, inspect_blob(b""))

    def test_hex_parsing(self):
        self.assertEqual(parse_hex("7f 45:4c46"), b"\x7fELF")
        with self.assertRaises(ValueError):
            parse_hex("abc")
        with self.assertRaises(ValueError):
            parse_hex("zz")
        with self.assertRaises(ValueError):
            inspect_blob(b"x", min_string_length=0)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(make_elf())
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                result = main(["--file", str(path)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(buffer.getvalue())["header"]["format"], "ELF")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(main(["--hex", "kernel".encode().hex()]), 0)
        self.assertEqual(json.loads(buffer.getvalue())["size"], 6)


if __name__ == "__main__":
    unittest.main()
