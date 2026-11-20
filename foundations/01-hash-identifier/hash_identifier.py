#!/usr/bin/env python3
"""Identify hash formats from their textual representation.

Pure-static analysis: no hashing, no cracking, no network access.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["HashMatch", "identify", "format_report"]


@dataclass(frozen=True)
class HashMatch:
    """A possible identification for an input string."""

    name: str
    confidence: str  # high | medium | low
    reason: str


_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BCRYPT = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")
_BCRYPT_PREFIX = re.compile(r"^\$2[aby]\$")
_PHC = re.compile(r"^\$(?P<alg>[A-Za-z0-9_-]+)(?:\$v=\d+)?\$")

_PHC_NAMES = {
    "argon2id": "Argon2id",
    "argon2i": "Argon2i",
    "argon2d": "Argon2d",
    "scrypt": "scrypt (PHC)",
    "pbkdf2-sha256": "PBKDF2-SHA256 (PHC)",
    "pbkdf2-sha512": "PBKDF2-SHA512 (PHC)",
}

_HEX_LENGTHS = {
    32: ("MD5 / NTLM / LM", "medium", "32 hex characters; length alone cannot separate them"),
    40: ("SHA-1", "high", "40 hex characters"),
    56: ("SHA-224", "high", "56 hex characters"),
    64: ("SHA-256", "high", "64 hex characters"),
    96: ("SHA-384", "high", "96 hex characters"),
    128: ("SHA-512", "high", "128 hex characters"),
}


def identify(value: str) -> list[HashMatch]:
    """Return candidate hash formats for *value*, ordered by confidence."""
    text = value.strip()
    if not text:
        return []

    if _BCRYPT.match(text):
        return [HashMatch("bcrypt", "high", "bcrypt prefix and 60-character encoded form")]

    if _BCRYPT_PREFIX.match(text):
        return [HashMatch("Malformed bcrypt", "low", "bcrypt prefix but not a 60-character encoded form")]

    phc = _PHC.match(text)
    if phc:
        alg = phc.group("alg").lower()
        name = _PHC_NAMES.get(alg)
        if name:
            return [HashMatch(name, "high", f"PHC prefix ${alg}$")]
        return [HashMatch(f"PHC string ({alg})", "medium", "unrecognised PHC algorithm identifier")]

    if _HEX.match(text):
        match = _HEX_LENGTHS.get(len(text))
        if match:
            name, confidence, reason = match
            return [HashMatch(name, confidence, reason)]
        return [HashMatch("Unknown hex string", "low", f"{len(text)} hex characters; no common digest length")]

    return [HashMatch("Unknown format", "low", "not hex, bcrypt, or a PHC string")]


def format_report(value: str, matches: list[HashMatch]) -> str:
    """Render a single identification result as text."""
    shown = value if len(value) <= 72 else value[:69] + "..."
    if not matches:
        return f"{shown}\n  no candidates"
    lines = [shown]
    for m in matches:
        lines.append(f"  [{m.confidence:6}] {m.name} — {m.reason}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Identify hash formats from text.")
    parser.add_argument("hash", nargs="?", help="hash string to inspect")
    parser.add_argument("-f", "--file", type=Path, help="file with one candidate per line")
    args = parser.parse_args(argv)

    if not args.hash and not args.file:
        parser.error("provide a hash string or --file")

    values: list[str] = []
    if args.hash:
        values.append(args.hash)
    if args.file:
        values.extend(line.rstrip("\r\n") for line in args.file.read_text(encoding="utf-8").splitlines())

    reports = [format_report(v, identify(v)) for v in values if v.strip()]
    print("\n\n".join(reports))
    return 0 if reports else 1


if __name__ == "__main__":
    sys.exit(main())
