import contextlib
import io
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from binary_analysis_tool import (  # noqa: E402
    analyze,
    describe,
    main,
    parse_elf,
    parse_pe,
)


def elf64(little=True, machine=0x3E, segments=True):
    endian = "<" if little else ">"
    ident = b"\x7fELF" + bytes([2, 1 if little else 2, 1, 0]) + b"\0" * 8
    phnum = 1 if segments else 0
    phoff = 64 if segments else 0
    shentsize = 64
    shoff = 64 + 56 * phnum
    shstr = b"\0.text\0.shstrtab\0"
    str_off = shoff + 3 * shentsize

    header = ident + struct.pack(
        endian + "HHIQQQIHHHHHH",
        2,
        machine,
        1,
        0x1000,
        phoff,
        shoff,
        0,
        64,
        56,
        phnum,
        shentsize,
        3,
        2,
    )
    phdr = struct.pack(endian + "IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, 0x100, 0x100, 0x1000)
    null_section = b"\0" * 64
    text_section = struct.pack(endian + "IIQQQQIIQQ", 1, 1, 6, 0x1000, 0x100, 0x20, 0, 0, 16, 0)
    str_section = struct.pack(endian + "IIQQQQIIQQ", 7, 3, 0, 0, str_off, len(shstr), 0, 0, 1, 0)
    return header + (phdr if segments else b"") + null_section + text_section + str_section + shstr


def elf32(little=True, machine=0x03):
    endian = "<" if little else ">"
    ident = b"\x7fELF" + bytes([1, 1 if little else 2, 1, 0]) + b"\0" * 8
    return ident + struct.pack(
        endian + "HHIIIIIHHHHHH", 2, machine, 1, 0x8048000, 0, 0, 0, 52, 32, 0, 40, 0, 0
    )


def pe(machine=0x8664, magic=0x20B, names=(b".text", b".rdata")):
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    optional_size = 32
    coff = struct.pack("<HHIIIHH", machine, len(names), 0, 0, 0, optional_size, 0x1022)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, magic)
    struct.pack_into("<I", optional, 16, 0x1000)

    sections = b"".join(
        struct.pack(
            "<8sIIIIIIHHI",
            name,
            0x20,
            0x1000 + 0x1000 * index,
            0x200,
            0x200 + 0x200 * index,
            0,
            0,
            0,
            0,
            0x60000020,
        )
        for index, name in enumerate(names)
    )
    return bytes(dos) + b"PE\0\0" + coff + bytes(optional) + sections


class BinaryAnalysisToolTests(unittest.TestCase):
    def test_elf64_header(self):
        report = parse_elf(elf64())
        self.assertEqual(report.elf_class, "ELF64")
        self.assertEqual(report.endianness, "little")
        self.assertEqual(report.machine, "x86-64")
        self.assertEqual(report.machine_code, 0x3E)

    def test_elf64_section_names(self):
        report = parse_elf(elf64())
        self.assertEqual([s.name for s in report.sections], ["section_0", ".text", ".shstrtab"])
        self.assertEqual(report.sections[1].type_name, "progbits")
        self.assertEqual(report.sections[1].address, 0x1000)
        self.assertEqual(report.sections[1].size, 0x20)

    def test_elf64_segments(self):
        report = parse_elf(elf64())
        self.assertEqual(len(report.segments), 1)
        self.assertEqual(report.segments[0].type_name, "load")
        self.assertEqual(report.segments[0].vaddr, 0x1000)
        self.assertEqual(parse_elf(elf64(segments=False)).segments, ())

    def test_elf32_little_endian(self):
        report = parse_elf(elf32())
        self.assertEqual(report.elf_class, "ELF32")
        self.assertEqual(report.endianness, "little")
        self.assertEqual(report.machine, "x86")
        self.assertEqual(report.sections, ())

    def test_elf32_big_endian(self):
        report = parse_elf(elf32(little=False, machine=0x14))
        self.assertEqual(report.endianness, "big")
        self.assertEqual(report.machine, "PowerPC")

    def test_unknown_machine_is_reported(self):
        self.assertIn("unknown", parse_elf(elf64(machine=0x1234)).machine)

    def test_truncated_elf(self):
        with self.assertRaises(ValueError):
            parse_elf(elf64()[:40])

    def test_unrecognized_format(self):
        with self.assertRaises(ValueError):
            analyze(b"not a binary")
        with self.assertRaises(ValueError):
            parse_pe(b"no dos header here")

    def test_pe32_plus_header(self):
        report = parse_pe(pe())
        self.assertEqual(report.pe_type, "PE32+")
        self.assertEqual(report.machine, "x86-64")
        self.assertEqual(report.entry_point, 0x1000)

    def test_pe_sections(self):
        report = parse_pe(pe())
        self.assertEqual([s.name for s in report.sections], [".text", ".rdata"])
        self.assertEqual(report.sections[1].virtual_address, 0x2000)
        self.assertEqual(report.sections[0].raw_offset, 0x200)

    def test_pe32_header(self):
        report = parse_pe(pe(machine=0x014C, magic=0x10B, names=(b".text",)))
        self.assertEqual(report.pe_type, "PE32")
        self.assertEqual(report.machine, "x86")

    def test_arm64_pe_machine(self):
        self.assertEqual(parse_pe(pe(machine=0xAA64)).machine, "ARM64")

    def test_truncated_pe_section_table(self):
        data = pe()
        with self.assertRaises(ValueError):
            parse_pe(data[: len(data) - 10])

    def test_describe(self):
        summary = describe(analyze(elf64()))
        self.assertIn("format: ELF", summary)
        self.assertIn(".text", summary)
        self.assertIn("format: PE", describe(analyze(pe())))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(elf64())
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["elf_class"], "ELF64")
            self.assertEqual(len(payload["sections"]), 3)


if __name__ == "__main__":
    unittest.main()
