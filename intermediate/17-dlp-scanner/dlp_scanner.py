#!/usr/bin/env python3
"""Scan synthetic text snapshots for PII/secret-like patterns and redact them.

Python-only project. Every fixture is synthetic: there are no real personal
records, credentials, or live services. The scanner reports matches and prints
redacted values only; it does not store raw matches in its CLI output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

__all__ = ["Finding", "luhn_valid", "redact", "scan_text"]

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_NATIONAL_ID_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]*){12,18}\d\b")
_API_KEY_RE = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,40}|sk-[A-Za-z0-9]{20,})\b"
)

_PATTERNS = (
    ("email", _EMAIL_RE, "low"),
    ("national-id-like", _NATIONAL_ID_RE, "high"),
    ("credit-card-like", _CARD_RE, "high"),
    ("api-key", _API_KEY_RE, "high"),
)


@dataclass(frozen=True)
class Finding:
    """A pattern match, including its redacted display form."""

    source: str
    kind: str
    severity: str
    match: str
    redacted: str
    start: int


def luhn_valid(digits: str) -> bool:
    """Return True when ``digits`` passes the Luhn checksum.

    Non-digit separators are ignored. Length is restricted to 13-19 digits,
    the range used by payment card numbers.
    """
    cleaned = "".join(character for character in digits if character.isdigit())
    if not 13 <= len(cleaned) <= 19:
        return False
    total = 0
    for position, character in enumerate(reversed(cleaned)):
        value = int(character)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def redact(value: str) -> str:
    """Mask the middle of ``value`` while keeping two leading/trailing characters."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def scan_text(text: str, source: str = "<text>") -> list[Finding]:
    """Find synthetic PII/secret-like strings, ordered by position then kind."""
    findings: list[Finding] = []
    for kind, pattern, severity in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if kind == "credit-card-like" and not luhn_valid(value):
                continue
            findings.append(
                Finding(
                    source=source,
                    kind=kind,
                    severity=severity,
                    match=value,
                    redacted=redact(value),
                    start=match.start(),
                )
            )
    findings.sort(key=lambda finding: (finding.start, finding.kind))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan synthetic text snapshots for PII/secret-like patterns."
    )
    parser.add_argument("snapshot", type=Path, help='JSON: {"label": "text to scan"}')
    args = parser.parse_args(argv)

    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise TypeError("snapshot must be a JSON object")
        all_findings = [
            finding
            for label in sorted(data)
            for finding in scan_text(str(data[label]), label)
        ]
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for finding in all_findings:
        print(
            f"[{finding.severity.upper():6}] {finding.source}: {finding.kind} "
            f"-> {finding.redacted}"
        )
    print(f"{len(all_findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
