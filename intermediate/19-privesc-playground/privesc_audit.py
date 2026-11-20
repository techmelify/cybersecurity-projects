#!/usr/bin/env python3
"""Read-only auditor for synthetic privilege-escalation indicators.

The tool consumes a JSON snapshot and reports risky configurations. It never
executes commands, changes permissions, contacts a live host, or describes
exploitation steps.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "SuidFile",
    "Directory",
    "Snapshot",
    "Finding",
    "parse_mode",
    "parse_snapshot",
    "audit",
    "summarize",
    "main",
]


@dataclass(frozen=True)
class SuidFile:
    path: str
    owner: str
    mode: int


@dataclass(frozen=True)
class Directory:
    path: str
    mode: int


@dataclass(frozen=True)
class Snapshot:
    suid_files: tuple[SuidFile, ...]
    sudoers_lines: tuple[str, ...]
    directories: tuple[Directory, ...]


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str  # low | medium | high
    detail: str
    recommendation: str


def parse_mode(value: int | str) -> int:
    """Return an octal bitmask from an octal string or integer of octal digits."""
    if isinstance(value, bool):
        raise ValueError("mode must be an octal string or integer")
    text = str(value).strip()
    if not text:
        raise ValueError("mode is empty")
    if any(char not in "01234567" for char in text):
        raise ValueError(f"invalid octal mode: {value!r}")
    return int(text, 8)


def parse_snapshot(data: Mapping[str, Any]) -> Snapshot:
    """Convert a decoded JSON mapping into immutable snapshot records."""
    suid_files = tuple(
        SuidFile(
            path=str(item["path"]),
            owner=str(item.get("owner", "unknown")),
            mode=parse_mode(item["mode"]),
        )
        for item in data.get("suid_files", [])
    )
    sudoers_lines = tuple(str(line) for line in data.get("sudoers_lines", []))
    directories = tuple(
        Directory(path=str(item["path"]), mode=parse_mode(item["mode"]))
        for item in data.get("world_writable_dirs", [])
    )
    return Snapshot(suid_files, sudoers_lines, directories)


def _sudo_code(line: str) -> str:
    return " ".join(line.split("#", 1)[0].split())


def audit(snapshot: Snapshot) -> list[Finding]:
    """Audit the snapshot and return deterministic, de-duplicated findings."""
    findings: list[Finding] = []

    for item in sorted(snapshot.suid_files, key=lambda entry: entry.path):
        if not item.mode & 0o4000:
            continue
        if item.mode & 0o002:
            findings.append(
                Finding(
                    "SUID-002",
                    "Setuid file is group/world writable",
                    "high",
                    f"{item.path} mode={item.mode:04o} owner={item.owner}",
                    "Remove write bits from setuid files and review ownership.",
                )
            )
        if item.owner == "root" and item.mode & 0o001:
            findings.append(
                Finding(
                    "SUID-001",
                    "Root-owned setuid file is world executable",
                    "high",
                    f"{item.path} mode={item.mode:04o} owner={item.owner}",
                    "Confirm the file is required; otherwise remove the setuid bit.",
                )
            )
        elif item.owner != "root":
            findings.append(
                Finding(
                    "SUID-003",
                    "Setuid file has a non-root owner",
                    "medium",
                    f"{item.path} owner={item.owner}",
                    "Review whether this owner needs elevated file capabilities.",
                )
            )

    sudoers_lines = [_sudo_code(line) for line in snapshot.sudoers_lines]
    sudoers_lines = [line for line in sudoers_lines if line]
    has_env_reset = any("env_reset" in line.lower() for line in sudoers_lines)
    negates_env_reset = any("!env_reset" in line.lower() for line in sudoers_lines)

    for line in sudoers_lines:
        lowered = line.lower()
        nopasswd = "nopasswd:" in lowered or "!authenticate" in lowered
        grants_all = bool(re.search(r"(?:\)\s*|:\s*)\bALL\b", line))
        if nopasswd and grants_all:
            findings.append(
                Finding(
                    "SUDO-001",
                    "Passwordless rule grants all commands",
                    "high",
                    line,
                    "Replace broad NOPASSWD rules with a narrow command allowlist.",
                )
            )
        elif grants_all:
            findings.append(
                Finding(
                    "SUDO-002",
                    "Sudo rule grants an unrestricted command set",
                    "medium",
                    line,
                    "Restrict the rule to the minimum required commands.",
                )
            )
        elif "*" in line.split(")", 1)[-1]:
            findings.append(
                Finding(
                    "SUDO-003",
                    "Sudo rule uses a command wildcard",
                    "medium",
                    line,
                    "Prefer explicit command paths over wildcards.",
                )
            )

    if sudoers_lines and (not has_env_reset or negates_env_reset):
        findings.append(
            Finding(
                "SUDO-004",
                "Sudoers environment reset is not enforced",
                "low",
                "Defaults env_reset is absent or negated",
                "Keep env_reset enabled to limit inherited environment variables.",
            )
        )

    for directory in sorted(snapshot.directories, key=lambda entry: entry.path):
        if not directory.mode & 0o002:
            continue
        if not directory.mode & 0o1000:
            findings.append(
                Finding(
                    "DIR-001",
                    "World-writable directory lacks the sticky bit",
                    "high",
                    f"{directory.path} mode={directory.mode:04o}",
                    "Add the sticky bit or remove world-write permission.",
                )
            )
        prefix = directory.path.rstrip("/") + "/"
        for item in snapshot.suid_files:
            if (
                item.owner == "root"
                and item.mode & 0o4000
                and item.mode & 0o001
                and item.path.startswith(prefix)
            ):
                findings.append(
                    Finding(
                        "DIR-002",
                        "Setuid path sits under a writable directory",
                        "high",
                        f"{item.path} under {directory.path} mode={directory.mode:04o}",
                        "Move privileged executables out of writable directories.",
                    )
                )

    unique = {(finding.id, finding.detail): finding for finding in findings}
    return [unique[key] for key in sorted(unique)]


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {"low": 0, "medium": 0, "high": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a synthetic system snapshot for privilege-escalation indicators."
    )
    parser.add_argument("snapshot", type=Path, help="JSON system snapshot")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = parser.parse_args(argv)

    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        findings = audit(parse_snapshot(data))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2, sort_keys=True))
    else:
        for finding in findings:
            print(
                f"[{finding.severity.upper():6}] {finding.id} {finding.title}: "
                f"{finding.detail} -> {finding.recommendation}"
            )
        summary = summarize(findings)
        print("summary: " + ", ".join(f"{key}={value}" for key, value in summary.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
