#!/usr/bin/env python3
"""Audit a Dockerfile/config text snapshot for container hardening indicators.

The tool parses text only. It never talks to a Docker daemon, builds images, or
starts containers. Secrets are reported by key name; values are not printed.
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
    "Snapshot",
    "Finding",
    "parse_snapshot",
    "parse_dockerfile_instructions",
    "parse_config_assignments",
    "audit",
    "main",
]


@dataclass(frozen=True)
class Snapshot:
    dockerfile: str
    config: str


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str  # low | medium | high
    detail: str
    recommendation: str


_SECRET_KEY_RE = re.compile(
    r"(?:^|[_.-])(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|KEY|CREDENTIAL)(?:[_.-]|$)",
    re.IGNORECASE,
)
_HOST_MOUNT_RE = re.compile(
    r"^\s*-\s+((?:/|\.{1,2}/)[^\s:]*):([^\s:]+)(?::[^\s]+)?\s*$"
)
_SENSITIVE_HOST_PATHS = (
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/var/run/docker.sock",
)
_TRUE_VALUES = frozenset({"true", "yes", "1", "on"})


def parse_snapshot(data: Mapping[str, Any]) -> Snapshot:
    return Snapshot(
        dockerfile=str(data.get("dockerfile", "")),
        config=str(data.get("config", data.get("compose", ""))),
    )


def parse_dockerfile_instructions(text: str) -> tuple[tuple[str, str], ...]:
    """Return (INSTRUCTION, arguments) pairs, honoring simple line continuations."""
    logical: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if buffer:
            line = buffer + " " + line
        if line.endswith("\\"):
            buffer = line[:-1].rstrip()
            continue
        buffer = ""
        logical.append(line)
    if buffer:
        logical.append(buffer)

    instructions = []
    for line in logical:
        instruction, _, args = line.partition(" ")
        instructions.append((instruction.upper(), args.strip()))
    return tuple(instructions)


def parse_config_assignments(text: str) -> tuple[tuple[str, str], ...]:
    """Extract simple key/value pairs from compose-like config text."""
    assignments: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        if "=" in line:
            key, _, value = line.partition("=")
        elif ":" in line:
            key, _, value = line.partition(":")
        else:
            continue
        assignments.append((key.strip().strip("\"'"), value.strip().strip("\"'")))
    return tuple(assignments)


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key))


def _is_sensitive_host_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    for sensitive in _SENSITIVE_HOST_PATHS:
        if normalized == sensitive or normalized.startswith(sensitive + "/"):
            return True
    return False


def _image_tag(spec: str) -> str | None:
    """Return 'latest', a tag name, 'digest', or None when the tag is implicit."""
    spec = spec.strip().strip("\"'")
    if "@" in spec:
        return "digest"
    tokens = [token for token in spec.split() if not token.startswith("--")]
    if not tokens:
        return None
    image = tokens[0]
    tail = image.rsplit(":", 1)
    if len(tail) == 1 or "/" in tail[1]:
        return None
    return tail[1]


def audit(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    instructions = parse_dockerfile_instructions(snapshot.dockerfile)
    assignments = parse_config_assignments(snapshot.config)

    user_values = [args.split()[0] for instruction, args in instructions if instruction == "USER" and args.split()]
    for key, value in assignments:
        if key.lower() == "user":
            user_values.append(value)
    if user_values and user_values[-1].strip().lower() in {"root", "0", "root:root", "0:0"}:
        findings.append(
            Finding(
                "DOCK-001",
                "Container runs as root",
                "high",
                f"effective user is {user_values[-1].strip()}",
                "Add a non-root USER instruction or run the container with a non-root identity.",
            )
        )
    elif not user_values:
        findings.append(
            Finding(
                "DOCK-001",
                "No non-root user declared",
                "medium",
                "no USER instruction or user setting found",
                "Declare an explicit unprivileged user.",
            )
        )

    privileged_config = any(
        key.lower() == "privileged" and value.lower() in _TRUE_VALUES for key, value in assignments
    )
    privileged_flag = "--privileged" in snapshot.config or any(
        "--privileged" in args for _, args in instructions
    )
    if privileged_config or privileged_flag:
        findings.append(
            Finding(
                "DOCK-002",
                "Privileged mode requested",
                "high",
                "privileged mode is enabled in the snapshot",
                "Remove privileged mode and grant only the specific capabilities required.",
            )
        )

    for raw in snapshot.config.splitlines():
        line = raw.strip().strip("\"'")
        match = _HOST_MOUNT_RE.match(line)
        if not match:
            continue
        host, container = match.group(1), match.group(2)
        severity = "high" if _is_sensitive_host_path(host) else "medium"
        findings.append(
            Finding(
                "DOCK-003",
                "Host path mounted into container",
                severity,
                f"host path {host} mapped to {container}",
                "Avoid bind mounts of host paths; use named volumes or restricted, explicit paths.",
            )
        )

    image_specs: list[str] = []
    for instruction, args in instructions:
        if instruction == "FROM":
            tokens = [token for token in args.split() if not token.startswith("--")]
            if tokens:
                image_specs.append(tokens[0])
    for key, value in assignments:
        if key.lower() == "image" and value:
            image_specs.append(value.split()[0])

    for spec in image_specs:
        tag = _image_tag(spec)
        if tag == "latest":
            findings.append(
                Finding(
                    "DOCK-004",
                    "Mutable latest image tag",
                    "medium",
                    f"image {spec} uses :latest",
                    "Pin images to a specific version or digest for reproducible builds.",
                )
            )
        elif tag is None:
            findings.append(
                Finding(
                    "DOCK-004",
                    "Image tag is implicit latest",
                    "medium",
                    f"image {spec} has no explicit tag",
                    "Add an explicit version tag or digest.",
                )
            )

    secret_sources: list[str] = []
    for instruction, args in instructions:
        if instruction not in {"ENV", "ARG"}:
            continue
        tokens = args.replace(",", " ").split()
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if "=" in token:
                key, value = token.split("=", 1)
                index += 1
            else:
                key = token
                value = tokens[index + 1] if index + 1 < len(tokens) else ""
                index += 2
            if _is_secret_key(key) and value and not value.startswith("${"):
                secret_sources.append(f"{key} in Dockerfile {instruction}")
    for key, value in assignments:
        if _is_secret_key(key) and value and not value.startswith("${"):
            secret_sources.append(f"{key} in config")
    for source in secret_sources:
        findings.append(
            Finding(
                "DOCK-005",
                "Potential secret in build/config text",
                "high",
                f"{source} has an inline value (value omitted)",
                "Inject secrets at runtime from a secret manager; never bake them into images or config.",
            )
        )

    unique = {(finding.id, finding.detail): finding for finding in findings}
    return [unique[key] for key in sorted(unique)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a Dockerfile/config text snapshot for container hardening indicators."
    )
    parser.add_argument("snapshot", type=Path, help="JSON snapshot with dockerfile/config text")
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
        print(f"findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
