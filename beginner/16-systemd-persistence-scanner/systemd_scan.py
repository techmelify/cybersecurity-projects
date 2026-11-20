#!/usr/bin/env python3
"""Read-only scanner for suspicious systemd unit definitions."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

__all__ = ["Finding", "scan_unit", "scan_units"]

_EXEC_KEYS = ("execstart", "execstartpre", "execstartpost", "execstop", "execstoppost")
_BAD_PATHS = ("/tmp/", "/var/tmp/", "/dev/shm/")
_BAD_TOKENS = ("curl ", "wget ", "base64 -d", "python -c", "python3 -c", "/bin/sh -c", "bash -c")


@dataclass(frozen=True)
class Finding:
    unit: str
    severity: str  # high | medium | low
    reason: str
    evidence: str


def scan_unit(name: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    directives: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        directives.append((key.strip().lower(), value.strip()))

    for key, value in directives:
        if key in _EXEC_KEYS:
            lowered = value.lower()
            for bad in _BAD_PATHS:
                if bad in lowered:
                    findings.append(Finding(name, "high", f"executes from writable path {bad}", value))
                    break
            for token in _BAD_TOKENS:
                if token in lowered:
                    findings.append(Finding(name, "medium", f"uses suspicious command '{token.strip()}'", value))
                    break

    values = {k: v for k, v in directives}
    if values.get("user", "").lower() == "root" and any(f.severity == "high" for f in findings):
        findings.append(Finding(name, "high", "runs as root with a writable-path executable", values["user"]))
    if values.get("restart", "").lower() == "always" and findings:
        findings.append(Finding(name, "medium", "persistent restart increases impact of suspicious command", values["restart"]))
    return findings


def scan_units(units: Mapping[str, str]) -> list[Finding]:
    result: list[Finding] = []
    for name, text in sorted(units.items()):
        result.extend(scan_unit(name, text))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan systemd unit definitions from a JSON snapshot.")
    parser.add_argument("snapshot", type=Path, help='JSON: {"unit-name.service": "..."}')
    args = parser.parse_args(argv)
    try:
        units = json.loads(args.snapshot.read_text(encoding="utf-8"))
        findings = scan_units(units)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"[{finding.severity.upper():6}] {finding.unit}: {finding.reason}")
    print(f"{len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
