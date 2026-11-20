#!/usr/bin/env python3
"""Defensive detector for layered text obfuscation indicators.

This is a defensive substitution for an offensive obfuscation engine: it only
scores text. It contains no encoder, no XOR implementation, and never emits a
transformed payload. Decoding happens solely to validate that a candidate run
is really encoded text; decoded bytes are discarded.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "Indicator",
    "Detection",
    "WEIGHTS",
    "analyze_text",
    "level_for_score",
    "format_report",
]

WEIGHTS: dict[str, int] = {
    "base64": 20,
    "hex": 20,
    "hex_escapes": 15,
    "unicode_escapes": 10,
    "escaped_string": 15,
    "double_escape": 10,
    "xor_literal": 20,
    "xor_keyword": 15,
    "char_codes": 10,
    "layered_encoding": 15,
}

ENCODING_KINDS = frozenset({"base64", "hex", "hex_escapes", "unicode_escapes", "escaped_string"})

B64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:0[xX])?([0-9A-Fa-f]{32,})(?![0-9A-Fa-f])")
HEX_ESCAPE_RE = re.compile(r"\\x[0-9A-Fa-f]{2}")
UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9A-Fa-f]{4}")
GENERIC_ESCAPE_RE = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[ntr\"'])")
DOUBLE_ESCAPE_RE = re.compile(r"\\\\+")
XOR_LITERAL_RE = re.compile(
    r"(?:0[xX][0-9A-Fa-f]{1,2}|\d{1,3})\s*\^\s*(?:0[xX][0-9A-Fa-f]{1,2}|\d{1,3})"
)
XOR_WORD_RE = re.compile(r"\bxor(?:_key|key)?\b", re.IGNORECASE)
XOR_CONTEXT_RE = re.compile(r"key|mask|decod|decrypt|obfuscat", re.IGNORECASE)
CHAR_CODE_RE = re.compile(r"\b(?:chr|ord)\s*\(")


@dataclass(frozen=True)
class Indicator:
    kind: str
    detail: str
    weight: int
    offset: int


@dataclass(frozen=True)
class Detection:
    score: int
    level: str
    indicators: tuple[Indicator, ...]
    layers: int


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    visible = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
    return visible / len(data)


def _valid_base64(token: str) -> bytes:
    if len(token) % 4 != 0:
        return b""
    try:
        return base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return b""


def _valid_hex(token: str) -> bytes:
    if len(token) % 2 != 0:
        return b""
    try:
        return bytes.fromhex(token)
    except ValueError:
        return b""


def level_for_score(score: int) -> str:
    """Map a 0-100 score onto a stable severity label."""
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def analyze_text(text: str) -> Detection:
    """Return obfuscation indicators found in ``text`` and a bounded score.

    The function is pure: it never changes the input and never returns decoded
    content. Indicators are appended in a fixed order for reproducibility.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    indicators: list[Indicator] = []
    found_kinds: set[str] = set()

    for match in B64_RE.finditer(text):
        token = match.group(1)
        decoded = _valid_base64(token)
        if len(decoded) >= 12 and _printable_ratio(decoded) >= 0.85:
            indicators.append(
                Indicator(
                    "base64",
                    f"{len(token)} chars decode to {len(decoded)} bytes",
                    WEIGHTS["base64"],
                    match.start(),
                )
            )
            found_kinds.add("base64")
            break

    for match in HEX_RE.finditer(text):
        token = match.group(1)
        decoded = _valid_hex(token)
        if len(decoded) >= 12 and _printable_ratio(decoded) >= 0.85:
            indicators.append(
                Indicator(
                    "hex",
                    f"{len(token)} hex chars decode to {len(decoded)} bytes",
                    WEIGHTS["hex"],
                    match.start(),
                )
            )
            found_kinds.add("hex")
            break

    hex_escapes = HEX_ESCAPE_RE.findall(text)
    if len(hex_escapes) >= 8:
        indicators.append(
            Indicator("hex_escapes", f"{len(hex_escapes)} \\xNN sequences", WEIGHTS["hex_escapes"],
                      HEX_ESCAPE_RE.search(text).start())
        )
        found_kinds.add("hex_escapes")

    unicode_escapes = UNICODE_ESCAPE_RE.findall(text)
    if len(unicode_escapes) >= 6:
        indicators.append(
            Indicator("unicode_escapes", f"{len(unicode_escapes)} \\uNNNN sequences",
                      WEIGHTS["unicode_escapes"], UNICODE_ESCAPE_RE.search(text).start())
        )
        found_kinds.add("unicode_escapes")

    escapes = GENERIC_ESCAPE_RE.findall(text)
    if len(escapes) >= 12:
        indicators.append(
            Indicator("escaped_string", f"{len(escapes)} escape sequences", WEIGHTS["escaped_string"],
                      GENERIC_ESCAPE_RE.search(text).start())
        )
        found_kinds.add("escaped_string")

    doubles = DOUBLE_ESCAPE_RE.findall(text)
    if len(doubles) >= 4:
        indicators.append(
            Indicator("double_escape", f"{len(doubles)} doubled-backslash runs",
                      WEIGHTS["double_escape"], DOUBLE_ESCAPE_RE.search(text).start())
        )

    xor_literal = XOR_LITERAL_RE.search(text)
    if xor_literal:
        indicators.append(
            Indicator("xor_literal", "numeric XOR expression", WEIGHTS["xor_literal"], xor_literal.start())
        )

    xor_words = XOR_WORD_RE.findall(text)
    if xor_words and XOR_CONTEXT_RE.search(text):
        indicators.append(
            Indicator("xor_keyword", f"{len(xor_words)} XOR-related tokens",
                      WEIGHTS["xor_keyword"], XOR_WORD_RE.search(text).start())
        )

    char_codes = CHAR_CODE_RE.findall(text)
    if len(char_codes) >= 3:
        indicators.append(
            Indicator("char_codes", f"{len(char_codes)} chr()/ord() calls", WEIGHTS["char_codes"],
                      CHAR_CODE_RE.search(text).start())
        )

    layers = len(found_kinds)
    if layers >= 2:
        indicators.append(
            Indicator("layered_encoding", f"{layers} distinct encoding layers",
                      WEIGHTS["layered_encoding"], 0)
        )

    score = min(100, sum(indicator.weight for indicator in indicators))
    return Detection(score, level_for_score(score), tuple(indicators), layers)


def format_report(detection: Detection) -> str:
    lines = [
        f"Score: {detection.score}/100 ({detection.level})",
        f"Encoding layers: {detection.layers}",
    ]
    if not detection.indicators:
        lines.append("Indicators: none")
    for indicator in detection.indicators:
        lines.append(
            f"  [{indicator.weight:+3}] {indicator.kind} @{indicator.offset}: {indicator.detail}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score text for obfuscation indicators (defensive only).")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-t", "--text", help="text to inspect")
    source.add_argument("-f", "--file", type=Path, help="local file to inspect")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        text = args.text if args.text is not None else args.file.read_text(encoding="utf-8")
        detection = analyze_text(text)
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(asdict(detection), indent=2))
    else:
        print(format_report(detection))
    return 0


if __name__ == "__main__":
    sys.exit(main())
