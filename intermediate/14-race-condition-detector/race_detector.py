#!/usr/bin/env python3
"""Detect check-then-act (TOCTOU) risk in synthetic data.

Defensive substitution for the "Race Condition Exploiter" synopsis. This tool
analyses access-log timelines and source-code snippets supplied by the caller.
It never schedules, triggers, synchronises, or exploits a race condition.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "AccessEvent",
    "Finding",
    "analyze_timeline",
    "analyze_code",
    "load_events",
]

_CHECK_RE = re.compile(r"\b(?:exists|access|stat|check)\s*\(", re.IGNORECASE)
_ACT_RE = re.compile(r"\b(?:open|write|delete|unlink|remove|replace)\s*\(", re.IGNORECASE)


@dataclass(frozen=True)
class AccessEvent:
    """One synthetic access-log record with an explicit check/act phase."""

    timestamp: str  # ISO-8601, e.g. "2026-01-01T00:00:00"
    subject: str
    resource: str
    phase: str  # "check" or "act"


@dataclass(frozen=True)
class Finding:
    """A suspected check-then-act window in the supplied data."""

    kind: str
    target: str  # resource path or source filename
    subject: str
    detail: str
    severity: str


def analyze_timeline(
    events: Iterable[AccessEvent],
    window_seconds: float = 5.0,
) -> list[Finding]:
    """Flag acts on a resource by a different subject soon after a check.

    Events are ordered by timestamp first. A check for resource R is paired
    with every later act on R by another subject that falls inside the window.
    A shorter gap is scored more severely because the race window is tighter.
    """
    parsed = sorted(
        ((datetime.fromisoformat(event.timestamp), event) for event in events),
        key=lambda pair: pair[0],
    )
    checks: dict[str, list[tuple[datetime, AccessEvent]]] = {}
    findings: list[Finding] = []

    for moment, event in parsed:
        if event.phase == "check":
            checks.setdefault(event.resource, []).append((moment, event))
        elif event.phase == "act":
            for check_moment, check in checks.get(event.resource, []):
                gap = (moment - check_moment).total_seconds()
                if 0 <= gap <= window_seconds and check.subject != event.subject:
                    severity = "high" if gap <= window_seconds / 2 else "medium"
                    findings.append(
                        Finding(
                            kind="timeline-toctou",
                            target=event.resource,
                            subject=event.subject,
                            detail=(
                                f"check by {check.subject} followed by act "
                                f"after {gap:g}s"
                            ),
                            severity=severity,
                        )
                    )
    return findings


def analyze_code(sources: Mapping[str, str], lookahead: int = 3) -> list[Finding]:
    """Flag source lines where a check is followed shortly by an act call.

    This is a heuristic pattern scan, not a data-flow analysis. It is intended
    to point a reviewer at suspicious sequences in synthetic snippets.
    """
    findings: list[Finding] = []
    for name in sorted(sources):
        lines = sources[name].splitlines()
        for index, line in enumerate(lines):
            if not _CHECK_RE.search(line):
                continue
            stop = min(index + 1 + lookahead, len(lines))
            for later in range(index + 1, stop):
                if _ACT_RE.search(lines[later]):
                    findings.append(
                        Finding(
                            kind="code-toctou",
                            target=name,
                            subject="<source>",
                            detail=(
                                f"check at line {index + 1} followed by act "
                                f"at line {later + 1}"
                            ),
                            severity="medium",
                        )
                    )
                    break
    return findings


def load_events(data: Iterable[Mapping[str, object]]) -> list[AccessEvent]:
    """Parse a JSON list of access-log records into ``AccessEvent`` objects."""
    return [
        AccessEvent(
            str(item["timestamp"]),
            str(item["subject"]),
            str(item["resource"]),
            str(item["phase"]).lower(),
        )
        for item in data
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect TOCTOU risk in synthetic access logs or code snippets."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    timeline_parser = subparsers.add_parser("timeline", help="analyse synthetic access logs")
    timeline_parser.add_argument("snapshot", type=Path, help="JSON list of access events")
    timeline_parser.add_argument("--window", type=float, default=5.0, help="race window in seconds")

    code_parser = subparsers.add_parser("code", help="analyse synthetic source snippets")
    code_parser.add_argument("snapshot", type=Path, help='JSON: {"filename": "source text"}')

    args = parser.parse_args(argv)
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        if args.mode == "timeline":
            findings = analyze_timeline(load_events(data), args.window)
        else:
            if not isinstance(data, Mapping):
                raise TypeError("code snapshot must be a JSON object")
            findings = analyze_code(data)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for finding in findings:
        print(
            f"[{finding.severity.upper():6}] {finding.kind} {finding.target}: "
            f"{finding.detail}"
        )
    print(f"{len(findings)} potential TOCTOU finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
