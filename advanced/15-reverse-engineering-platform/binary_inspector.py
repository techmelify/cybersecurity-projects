#!/usr/bin/env python3
"""Static inspection of synthetic byte blobs.

Recognises ELF/PE headers, extracts printable ASCII strings and imported
library names, and reports byte entropy. It never executes, loads, or
interprets the bytes as code: everything is read-only parsing for lab use.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

__all__ = [
    "SectionInfo",
    "HeaderInfo",
    "StringFinding",
    "ImportFinding",
    "InspectionReport",
    "inspect_blob",
    "parse_hex",
]

ELF_MACHINES = {0x03: "x86", 0x28: "arm", 0x3E: "x86-64", 0xB7: "aarch64"}
PE_MACHINES = {0x014C: "x86", 0x8664: "x86-64", 0xAA64: "arm64", 0x01C0: "arm"}

_IMPORT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("kernel32.dll", re.compile(r"kernel32\.dll", re.IGNORECASE)),
    ("user32.dll", re.compile(r"user32\.dll", re.IGNORECASE)),
    ("advapi32.dll", re.compile(r"advapi32\.dll", re.IGNORECASE)),
    ("ntdll.dll", re.compile(r"ntdll\.dll", re.IGNORECASE)),
    ("ws2_32.dll", re.compile(r"ws2_32\.dll", re.IGNORECASE)),
    ("libc.so", re.compile(r"libc\.so(?:\.\d+)*", re.IGNORECASE)),
    ("libm.so", re.compile(r"libm\.so(?:\.\d+)*", re.IGNORECASE)),
    ("libpthread.so", re.compile(r"libpthread\.so(?:\.\d+)*", re.IGNORECASE)),
    ("libcrypto.so", re.compile(r"libcrypto\.so(?:\.\d+)*", re.IGNORECASE)),
    ("libssl.so", re.compile(r"libssl\.so(?:\.\d+)*", re.IGNORECASE)),
)
_GENERIC_LIBRARY = re.compile(r"[A-Za-z0-9_-]+\.(?:dll|dylib|so(?:\.\d+)*)\b", re.IGNORECASE)


@dataclass(frozen=True)
class SectionInfo:
    """A section entry with its table offset and declared raw size."""

    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class HeaderInfo:
    """Format-level facts recovered from the first bytes of a blob."""

    format: str
    magic: str
    architecture: str
    sections: tuple[SectionInfo, ...]


@dataclass(frozen=True)
class StringFinding:
    """A printable ASCII run and its byte offset."""

    offset: int
    value: str


@dataclass(frozen=True)
class ImportFinding:
    """A library name and the evidence that suggested it."""

    library: str
    evidence: str


@dataclass(frozen=True)
class InspectionReport:
    """Complete, deterministic report for one blob."""

    header: HeaderInfo
    strings: tuple[StringFinding, ...]
    imports: tuple[ImportFinding, ...]
    entropy: float
    size: int


def _read_uint(data: bytes, offset: int, width: int, little: bool = True) -> int:
    chunk = data[offset : offset + width]
    if len(chunk) < width:
        return 0
    return int.from_bytes(chunk, "little" if little else "big")


def _parse_elf(data: bytes) -> HeaderInfo:
    elf_class = data[4] if len(data) > 4 else 0
    little = not (len(data) > 5 and data[5] == 2)
    machine = _read_uint(data, 18, 2, little)
    architecture = ELF_MACHINES.get(machine, f"unknown-{machine:#x}")
    bits = {1: "32-bit", 2: "64-bit"}.get(elf_class, "unknown")

    if elf_class == 2:
        table_offset = _read_uint(data, 0x28, 8, little)
        entry_size = _read_uint(data, 0x3A, 2, little)
        count = _read_uint(data, 0x3C, 2, little)
        size_offset = 32
    else:
        table_offset = _read_uint(data, 0x20, 4, little)
        entry_size = _read_uint(data, 0x2E, 2, little)
        count = _read_uint(data, 0x30, 2, little)
        size_offset = 20

    sections: list[SectionInfo] = []
    if table_offset and entry_size >= size_offset + 8 and count:
        for index in range(min(count, 8)):
            base = table_offset + index * entry_size
            if base + size_offset + 8 > len(data):
                break
            width = 8 if elf_class == 2 else 4
            sections.append(
                SectionInfo(
                    f"section-{index}",
                    base,
                    _read_uint(data, base + size_offset, width, little),
                )
            )
    return HeaderInfo("ELF", data[:4].hex(), f"{architecture} ({bits})", tuple(sections))


def _parse_pe(data: bytes) -> HeaderInfo:
    pe_offset = _read_uint(data, 0x3C, 4, True)
    signature = data[pe_offset : pe_offset + 4]
    if signature != b"PE\0\0":
        return HeaderInfo("unknown", data[:4].hex(), "unknown", ())
    machine = _read_uint(data, pe_offset + 4, 2, True)
    count = _read_uint(data, pe_offset + 6, 2, True)
    optional_size = _read_uint(data, pe_offset + 20, 2, True)
    architecture = PE_MACHINES.get(machine, f"unknown-{machine:#x}")
    bits = "64-bit" if machine in {0x8664, 0xAA64} else "32-bit"

    sections: list[SectionInfo] = []
    table = pe_offset + 24 + optional_size
    for index in range(min(count, 8)):
        base = table + index * 40
        if base + 40 > len(data):
            break
        raw_name = data[base : base + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section-{index}"
        sections.append(SectionInfo(name, base, _read_uint(data, base + 16, 4, True)))
    return HeaderInfo("PE", signature.hex(), f"{architecture} ({bits})", tuple(sections))


def _parse_header(data: bytes) -> HeaderInfo:
    if data[:4] == b"\x7fELF":
        return _parse_elf(data)
    if data[:2] == b"MZ":
        return _parse_pe(data)
    return HeaderInfo("unknown", data[:4].hex(), "unknown", ())


def _printable_strings(
    data: bytes,
    min_length: int,
    max_strings: int,
    max_length: int,
) -> tuple[StringFinding, ...]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    results: list[StringFinding] = []
    for match in pattern.finditer(data):
        value = match.group().decode("ascii")[:max_length]
        results.append(StringFinding(match.start(), value))
        if len(results) >= max_strings:
            break
    return tuple(results)


def _imports(strings: Iterable[StringFinding], limit: int) -> tuple[ImportFinding, ...]:
    found: dict[str, str] = {}
    for name, pattern in _IMPORT_PATTERNS:
        for item in strings:
            if pattern.search(item.value):
                found[name] = f"string@{item.offset}"
                break
    for item in strings:
        for match in _GENERIC_LIBRARY.finditer(item.value):
            name = match.group(0).lower()
            found.setdefault(name, f"string@{item.offset}")
    ordered = sorted(found.items())[:limit]
    return tuple(ImportFinding(name, evidence) for name, evidence in ordered)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    score = 0.0
    for count in Counter(data).values():
        probability = count / total
        score -= probability * math.log2(probability)
    return round(score, 3)


def inspect_blob(
    data: bytes,
    *,
    min_string_length: int = 4,
    max_strings: int = 200,
    max_string_length: int = 120,
    max_imports: int = 20,
) -> InspectionReport:
    """Read-only inspection of a synthetic byte blob. Pure function."""
    if min_string_length < 1 or max_strings < 0:
        raise ValueError("invalid extraction limits")
    blob = bytes(data)
    strings = _printable_strings(blob, min_string_length, max_strings, max_string_length)
    return InspectionReport(
        header=_parse_header(blob),
        strings=strings,
        imports=_imports(strings, max_imports),
        entropy=_entropy(blob),
        size=len(blob),
    )


def parse_hex(text: str) -> bytes:
    """Convert a hex string (optional whitespace/colons) to bytes."""
    cleaned = re.sub(r"[\s:]", "", text)
    if len(cleaned) % 2:
        raise ValueError("hex input must have an even number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as error:
        raise ValueError("invalid hex input") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Statically inspect a synthetic byte blob.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="read a binary file")
    source.add_argument("--hex", help="hex-encoded blob")
    parser.add_argument("--min-string-length", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        blob = args.file.read_bytes() if args.file else parse_hex(args.hex or "")
        report = inspect_blob(blob, min_string_length=args.min_string_length)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(asdict(report), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
