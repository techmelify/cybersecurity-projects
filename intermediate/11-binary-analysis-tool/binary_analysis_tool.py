#!/usr/bin/env python3
"""Minimal pure-Python ELF and PE header parser.

Only headers and section/segment tables are inspected. Input is a bytes object
supplied by the caller (synthetic fixtures in tests); there is no malware
execution, loader interaction, or unpacking of payloads.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import asdict, dataclass
from typing import Sequence

__all__ = [
    "ElfSection",
    "ElfSegment",
    "ElfReport",
    "PeSection",
    "PeReport",
    "parse_elf",
    "parse_pe",
    "analyze",
    "describe",
    "main",
]

_ELF_MACHINES = {
    0x03: "x86",
    0x14: "PowerPC",
    0x28: "ARM",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}
_PE_MACHINES = {
    0x014C: "x86",
    0x01C4: "ARM",
    0x0200: "IA-64",
    0x8664: "x86-64",
    0xAA64: "ARM64",
}
_SECTION_TYPES = {
    0: "null",
    1: "progbits",
    2: "symtab",
    3: "strtab",
    4: "rela",
    8: "nobits",
    9: "rel",
    11: "dynamic",
    14: "init_array",
}
_SEGMENT_TYPES = {
    0: "null",
    1: "load",
    2: "dynamic",
    3: "interp",
    4: "note",
    6: "phdr",
    7: "tls",
    0x6474E551: "gnu_stack",
    0x6474E552: "gnu_relro",
}


@dataclass(frozen=True)
class ElfSection:
    name: str
    section_type: int
    type_name: str
    address: int
    offset: int
    size: int


@dataclass(frozen=True)
class ElfSegment:
    segment_type: int
    type_name: str
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int


@dataclass(frozen=True)
class ElfReport:
    elf_class: str
    endianness: str
    machine: str
    machine_code: int
    sections: tuple[ElfSection, ...]
    segments: tuple[ElfSegment, ...]

    @property
    def format(self) -> str:
        return "ELF"


@dataclass(frozen=True)
class PeSection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclass(frozen=True)
class PeReport:
    pe_type: str
    machine: str
    machine_code: int
    entry_point: int
    sections: tuple[PeSection, ...]

    @property
    def format(self) -> str:
        return "PE"


def _require(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"truncated {label}")


def _u16(data: bytes, offset: int, endian: str, label: str = "header") -> int:
    _require(data, offset, 2, label)
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str, label: str = "header") -> int:
    _require(data, offset, 4, label)
    return struct.unpack_from(endian + "I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str, label: str = "header") -> int:
    _require(data, offset, 8, label)
    return struct.unpack_from(endian + "Q", data, offset)[0]


def _cstring(data: bytes, offset: int, limit: int) -> str:
    if offset < 0 or offset >= limit or limit > len(data):
        return ""
    end = data.find(b"\0", offset, limit)
    return data[offset : end if end >= 0 else limit].decode("ascii", errors="replace")


def parse_elf(data: bytes) -> ElfReport:
    """Parse ELF32/ELF64 headers, sections, and program headers."""

    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    encoding = data[5]
    if elf_class not in (1, 2):
        raise ValueError(f"unsupported ELF class {elf_class}")
    if encoding not in (1, 2):
        raise ValueError(f"unsupported ELF data encoding {encoding}")
    endian = "<" if encoding == 1 else ">"
    is_64 = elf_class == 2
    endianness = "little" if encoding == 1 else "big"
    header_size = 64 if is_64 else 52
    _require(data, 0, header_size, "ELF header")

    machine_code = _u16(data, 18, endian)
    file_type = _u16(data, 16, endian)
    if file_type == 0:
        raise ValueError("ELF file has no object type")

    if is_64:
        phoff = _u64(data, 32, endian)
        shoff = _u64(data, 40, endian)
        phentsize = _u16(data, 54, endian)
        phnum = _u16(data, 56, endian)
        shentsize = _u16(data, 58, endian)
        shnum = _u16(data, 60, endian)
        shstrndx = _u16(data, 62, endian)
        minimum_shentsize, minimum_phentsize = 64, 56
    else:
        phoff = _u32(data, 28, endian)
        shoff = _u32(data, 32, endian)
        phentsize = _u16(data, 42, endian)
        phnum = _u16(data, 44, endian)
        shentsize = _u16(data, 46, endian)
        shnum = _u16(data, 48, endian)
        shstrndx = _u16(data, 50, endian)
        minimum_shentsize, minimum_phentsize = 40, 32

    if shnum and shentsize < minimum_shentsize:
        raise ValueError("ELF section header entry is too small")
    if phnum and phentsize < minimum_phentsize:
        raise ValueError("ELF program header entry is too small")
    if shnum:
        _require(data, shoff, shnum * shentsize, "ELF section table")
    if phnum:
        _require(data, phoff, phnum * phentsize, "ELF program table")

    name_table = b""
    if 0 < shstrndx < shnum:
        entry = shoff + shstrndx * shentsize
        if is_64:
            table_offset = _u64(data, entry + 24, endian, "ELF section header")
            name_size = _u64(data, entry + 32, endian, "ELF section header")
        else:
            table_offset = _u32(data, entry + 16, endian, "ELF section header")
            name_size = _u32(data, entry + 20, endian, "ELF section header")
        _require(data, table_offset, name_size, "ELF string table")
        name_table = data[table_offset : table_offset + name_size]

    sections: list[ElfSection] = []
    for index in range(shnum):
        entry = shoff + index * shentsize
        name_index = _u32(data, entry, endian, "ELF section header")
        section_type = _u32(data, entry + 4, endian, "ELF section header")
        if is_64:
            address = _u64(data, entry + 16, endian, "ELF section header")
            offset = _u64(data, entry + 24, endian, "ELF section header")
            size = _u64(data, entry + 32, endian, "ELF section header")
        else:
            address = _u32(data, entry + 12, endian, "ELF section header")
            offset = _u32(data, entry + 16, endian, "ELF section header")
            size = _u32(data, entry + 20, endian, "ELF section header")
        name = _cstring(name_table, name_index, len(name_table))
        sections.append(
            ElfSection(
                name or f"section_{index}",
                section_type,
                _SECTION_TYPES.get(section_type, f"type_{section_type}"),
                address,
                offset,
                size,
            )
        )

    segments: list[ElfSegment] = []
    for index in range(phnum):
        entry = phoff + index * phentsize
        segment_type = _u32(data, entry, endian, "ELF program header")
        if is_64:
            flags = _u32(data, entry + 4, endian, "ELF program header")
            offset = _u64(data, entry + 8, endian, "ELF program header")
            vaddr = _u64(data, entry + 16, endian, "ELF program header")
            filesz = _u64(data, entry + 32, endian, "ELF program header")
            memsz = _u64(data, entry + 40, endian, "ELF program header")
        else:
            offset = _u32(data, entry + 4, endian, "ELF program header")
            vaddr = _u32(data, entry + 8, endian, "ELF program header")
            filesz = _u32(data, entry + 16, endian, "ELF program header")
            memsz = _u32(data, entry + 20, endian, "ELF program header")
            flags = _u32(data, entry + 24, endian, "ELF program header")
        segments.append(
            ElfSegment(
                segment_type,
                _SEGMENT_TYPES.get(segment_type, f"type_{segment_type}"),
                offset,
                vaddr,
                filesz,
                memsz,
                flags,
            )
        )

    return ElfReport(
        f"ELF{64 if is_64 else 32}",
        endianness,
        _ELF_MACHINES.get(machine_code, f"unknown ({machine_code:#x})"),
        machine_code,
        tuple(sections),
        tuple(segments),
    )


def parse_pe(data: bytes) -> PeReport:
    """Parse PE32/PE32+ COFF header and section table."""

    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe_offset = _u32(data, 0x3C, "<", "DOS header")
    _require(data, pe_offset, 24, "PE signature and COFF header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")

    coff = pe_offset + 4
    machine_code = _u16(data, coff, "<", "COFF header")
    section_count = _u16(data, coff + 2, "<", "COFF header")
    optional_size = _u16(data, coff + 16, "<", "COFF header")
    optional = coff + 20
    _require(data, optional, optional_size, "PE optional header")

    if optional_size < 2:
        raise ValueError("PE optional header is too small")
    magic = _u16(data, optional, "<", "PE optional header")
    if magic == 0x10B:
        pe_type = "PE32"
    elif magic == 0x20B:
        pe_type = "PE32+"
    else:
        raise ValueError(f"unsupported PE optional header magic {magic:#x}")
    entry_point = _u32(data, optional + 16, "<", "PE optional header") if optional_size >= 20 else 0

    table = optional + optional_size
    _require(data, table, section_count * 40, "PE section table")
    sections: list[PeSection] = []
    for index in range(section_count):
        entry = table + index * 40
        raw_name = data[entry : entry + 8]
        sections.append(
            PeSection(
                raw_name.rstrip(b"\0").decode("ascii", errors="replace"),
                _u32(data, entry + 8, "<", "PE section header"),
                _u32(data, entry + 12, "<", "PE section header"),
                _u32(data, entry + 16, "<", "PE section header"),
                _u32(data, entry + 20, "<", "PE section header"),
                _u32(data, entry + 36, "<", "PE section header"),
            )
        )

    return PeReport(
        pe_type,
        _PE_MACHINES.get(machine_code, f"unknown ({machine_code:#x})"),
        machine_code,
        entry_point,
        tuple(sections),
    )


def analyze(data: bytes) -> ElfReport | PeReport:
    """Dispatch to the ELF or PE parser based on the file magic."""

    if data.startswith(b"\x7fELF"):
        return parse_elf(data)
    if data.startswith(b"MZ"):
        return parse_pe(data)
    raise ValueError("unrecognized binary format (expected ELF or PE magic)")


def describe(report: ElfReport | PeReport) -> str:
    """Return a compact, human-readable summary."""

    lines = [
        f"format: {report.format}",
        f"type: {report.elf_class if isinstance(report, ElfReport) else report.pe_type}",
        f"machine: {report.machine} ({report.machine_code:#x})",
    ]
    if isinstance(report, ElfReport):
        lines.append(f"endianness: {report.endianness}")
        lines.append(f"sections ({len(report.sections)}):")
        lines.extend(f"  {s.name} {s.type_name} addr={s.address:#x} size={s.size:#x}" for s in report.sections)
        lines.append(f"segments ({len(report.segments)}):")
        lines.extend(f"  {s.type_name} vaddr={s.vaddr:#x} filesz={s.filesz:#x}" for s in report.segments)
    else:
        lines.append(f"entry_point: {report.entry_point:#x}")
        lines.append(f"sections ({len(report.sections)}):")
        lines.extend(
            f"  {s.name} va={s.virtual_address:#x} raw_size={s.raw_size:#x}" for s in report.sections
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse ELF/PE headers from a local binary file.")
    parser.add_argument("file", help="path to a local binary file")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args(argv)

    from pathlib import Path

    try:
        report = analyze(Path(args.file).read_bytes())
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
        return 2

    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print(describe(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
