#!/usr/bin/env python3
"""Offline secrets scanner over a snapshot of text files.

The scanner never walks a filesystem on its own and never opens a network
connection: callers supply a mapping of ``path -> text`` (a "snapshot").
All findings are masked so that printing a report does not re-leak a secret.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence

__all__ = [
    "ScanConfig",
    "Finding",
    "ScanResult",
    "shannon_entropy",
    "scan_text",
    "scan_snapshot",
    "main",
]


@dataclass(frozen=True)
class ScanConfig:
    """Tunable, immutable scanner settings."""

    min_entropy: float = 3.5
    min_length: int = 24
    suppression_markers: tuple[str, ...] = (
        "nosec",
        "pragma: allowlist secret",
        "secrets-scanner: ignore",
    )
    file_disable_marker: str = "secrets-scanner: disable-file"


@dataclass(frozen=True)
class Finding:
    """One masked secret candidate."""

    path: str
    line: int
    column: int
    kind: str
    masked_value: str
    entropy: float

    @property
    def message(self) -> str:
        return (
            f"{self.path}:{self.line}:{self.column} {self.kind} "
            f"(entropy={self.entropy:.2f}) {self.masked_value}"
        )


@dataclass(frozen=True)
class ScanResult:
    """Aggregate result for one snapshot."""

    findings: tuple[Finding, ...]
    scanned_files: int
    suppressed: int

    @property
    def ok(self) -> bool:
        return not self.findings


# Patterns for well-known credential shapes. These are shape checks only; the
# values used in the unit tests are synthetic and are not live credentials.
_SPECIFIC_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "private_key_header",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
)

_ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9+/=_-])")


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy (bits per character) of ``value``."""

    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-2:]}"


def _has_mixed_classes(value: str) -> bool:
    return any(char.isalpha() for char in value) and any(char.isdigit() for char in value)


def _line_and_column(text: str, position: int) -> tuple[int, int]:
    line = text.count("\n", 0, position) + 1
    previous_newline = text.rfind("\n", 0, position)
    return line, position - previous_newline


def _is_suppressed(line: str, config: ScanConfig) -> bool:
    lowered = line.lower()
    return any(marker.lower() in lowered for marker in config.suppression_markers)


def scan_text(
    text: str,
    path: str = "<memory>",
    config: ScanConfig | None = None,
) -> tuple[tuple[Finding, ...], int]:
    """Scan one text blob.

    Returns ``(findings, suppressed_count)``. Suppression is line based: a
    marker such as ``# nosec`` silences candidates on that line only, while a
    file-level marker in the first ten lines silences the whole file.
    """

    settings = config or ScanConfig()
    lines = text.splitlines()
    file_disabled = any(
        settings.file_disable_marker in line for line in lines[:10]
    )

    # (start, end, kind, entropy, raw value)
    candidates: list[tuple[int, int, str, float, str]] = []
    for kind, pattern in _SPECIFIC_PATTERNS:
        for match in pattern.finditer(text):
            candidates.append((match.start(), match.end(), kind, 0.0, match.group(0)))

    for match in _ENTROPY_CANDIDATE.finditer(text):
        token = match.group(0)
        entropy = shannon_entropy(token)
        if (
            len(token) >= settings.min_length
            and entropy >= settings.min_entropy
            and _has_mixed_classes(token)
        ):
            candidates.append((match.start(), match.end(), "high_entropy_token", entropy, token))

    # Specific patterns win over generic high-entropy matches on the same span.
    candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    non_overlapping: list[tuple[int, int, str, float, str]] = []
    last_end = -1
    for candidate in candidates:
        if candidate[0] < last_end:
            continue
        non_overlapping.append(candidate)
        last_end = candidate[1]

    findings: list[Finding] = []
    suppressed = 0
    for start, _end, kind, entropy, value in non_overlapping:
        line, column = _line_and_column(text, start)
        if file_disabled or _is_suppressed(lines[line - 1], settings):
            suppressed += 1
            continue
        findings.append(Finding(path, line, column, kind, _mask(value), entropy))
    return tuple(findings), suppressed


def scan_snapshot(
    snapshot: Mapping[str, str],
    config: ScanConfig | None = None,
) -> ScanResult:
    """Scan a ``path -> text`` snapshot without touching the filesystem."""

    all_findings: list[Finding] = []
    suppressed = 0
    for path, text in sorted(snapshot.items()):
        findings, hidden = scan_text(text, path=path, config=config)
        all_findings.extend(findings)
        suppressed += hidden
    return ScanResult(tuple(all_findings), len(snapshot), suppressed)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan text snapshots for likely secrets.")
    parser.add_argument("paths", nargs="*", help="local text files to read")
    parser.add_argument("--min-entropy", type=float, default=ScanConfig.min_entropy)
    parser.add_argument("--min-length", type=int, default=ScanConfig.min_length)
    parser.add_argument("--json", action="store_true", help="emit JSON findings")
    args = parser.parse_args(argv)

    if not args.paths:
        parser.error("supply at least one file path")

    snapshot: dict[str, str] = {}
    for name in args.paths:
        from pathlib import Path

        path = Path(name)
        snapshot[str(path)] = path.read_text(encoding="utf-8", errors="replace")

    config = ScanConfig(min_entropy=args.min_entropy, min_length=args.min_length)
    result = scan_snapshot(snapshot, config)
    if args.json:
        print(json.dumps([asdict(f) for f in result.findings], indent=2))
    else:
        for finding in result.findings:
            print(finding.message)
        print(
            f"{len(result.findings)} finding(s) in {result.scanned_files} file(s), "
            f"{result.suppressed} suppressed"
        )
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
