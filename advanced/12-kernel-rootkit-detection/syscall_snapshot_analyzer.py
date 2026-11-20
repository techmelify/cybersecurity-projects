#!/usr/bin/env python3
"""Analyze a synthetic syscall-table snapshot for rootkit-style indicators.

The input is a JSON document supplied by the caller. This tool never reads
kernel memory, loads modules, touches /proc, or inspects a live system.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

__all__ = [
    "SyscallEntry",
    "ProcessEntry",
    "Snapshot",
    "Detection",
    "DetectionReport",
    "load_snapshot",
    "parse_snapshot",
    "analyze_snapshot",
    "main",
]


@dataclass(frozen=True)
class SyscallEntry:
    number: int
    name: str
    handler: str
    module: str
    expected_handler: str | None = None


@dataclass(frozen=True)
class ProcessEntry:
    pid: int
    name: str
    visible_in_proc: bool
    listed_by_ps: bool
    hidden: bool = False


@dataclass(frozen=True)
class Snapshot:
    syscalls: tuple[SyscallEntry, ...]
    processes: tuple[ProcessEntry, ...]
    allowed_modules: frozenset[str]


@dataclass(frozen=True)
class Detection:
    rule_id: str
    severity: str
    subject: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "subject": self.subject,
            "message": self.message,
        }


@dataclass(frozen=True)
class DetectionReport:
    detections: tuple[Detection, ...]

    def counts(self) -> dict[str, int]:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for detection in self.detections:
            counts[detection.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "note": "Synthetic snapshot analysis only; no kernel access.",
            "total": len(self.detections),
            "counts": self.counts(),
            "detections": [detection.as_dict() for detection in self.detections],
        }

    def format_text(self) -> str:
        counts = self.counts()
        lines = [
            "Synthetic syscall snapshot analysis (no kernel access).",
            f"Detections: {len(self.detections)}",
        ]
        lines.extend(
            f"  {level}: {counts[level]}"
            for level in reversed(tuple(SEVERITY_ORDER))
        )
        lines.append("")
        if not self.detections:
            lines.append("No rootkit-style indicators in this snapshot.")
            return "\n".join(lines)
        for detection in self.detections:
            lines.append(
                f"[{detection.severity.upper()}] {detection.rule_id} "
                f"{detection.subject}: {detection.message}"
            )
        return "\n".join(lines)


def _as_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


def _as_bool(value: Any, field: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _rows(data: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = data.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a JSON array")
    result: list[Mapping[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, Mapping):
            raise ValueError(f"{key}[{index}] must be a JSON object")
        result.append(row)
    return result


def load_snapshot(path: Path) -> Mapping[str, Any]:
    """Load a JSON snapshot and validate its root type."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("snapshot root must be a JSON object")
    return data


def parse_snapshot(data: Mapping[str, Any]) -> Snapshot:
    """Convert an untyped JSON mapping into validated snapshot dataclasses."""
    if not isinstance(data, Mapping):
        raise ValueError("snapshot must be a JSON object")

    allowed_raw = data.get("allowed_modules", ["kernel"])
    if not isinstance(allowed_raw, list) or any(
        not isinstance(item, str) for item in allowed_raw
    ):
        raise ValueError("allowed_modules must be an array of strings")
    allowed_modules = frozenset(item.strip() for item in allowed_raw if item.strip())

    syscalls: list[SyscallEntry] = []
    for index, row in enumerate(_rows(data, "syscalls")):
        number = _as_int(row.get("number"), f"syscalls[{index}].number")
        name = str(row.get("name") or f"syscall-{number}")
        handler = str(row.get("handler") or "")
        module = str(row.get("module") or "kernel")
        expected_raw = row.get("expected_handler")
        expected = None if expected_raw is None else str(expected_raw)
        syscalls.append(SyscallEntry(number, name, handler, module, expected))

    processes: list[ProcessEntry] = []
    for index, row in enumerate(_rows(data, "processes")):
        pid = _as_int(row.get("pid"), f"processes[{index}].pid")
        name = str(row.get("name") or f"pid-{pid}")
        processes.append(
            ProcessEntry(
                pid=pid,
                name=name,
                visible_in_proc=_as_bool(
                    row.get("visible_in_proc"),
                    f"processes[{index}].visible_in_proc",
                    True,
                ),
                listed_by_ps=_as_bool(
                    row.get("listed_by_ps"),
                    f"processes[{index}].listed_by_ps",
                    True,
                ),
                hidden=_as_bool(
                    row.get("hidden"), f"processes[{index}].hidden", False
                ),
            )
        )
    return Snapshot(tuple(syscalls), tuple(processes), allowed_modules)


def analyze_snapshot(snapshot: Snapshot) -> DetectionReport:
    """Apply deterministic rootkit-style heuristics to a parsed snapshot."""
    detections: list[Detection] = []

    for entry in snapshot.syscalls:
        subject = f"syscall {entry.number} {entry.name}"
        if entry.expected_handler is not None and entry.handler != entry.expected_handler:
            detections.append(
                Detection(
                    "KRN-HOOK-001",
                    "critical",
                    subject,
                    (
                        f"handler {entry.handler!r} differs from expected "
                        f"{entry.expected_handler!r}"
                    ),
                )
            )
        if entry.module not in snapshot.allowed_modules:
            detections.append(
                Detection(
                    "KRN-MOD-001",
                    "high",
                    subject,
                    f"unexpected owning module {entry.module!r}",
                )
            )

    for process in snapshot.processes:
        subject = f"pid {process.pid} ({process.name})"
        reasons: list[str] = []
        if process.hidden:
            reasons.append("explicit hidden flag")
        if not process.visible_in_proc:
            reasons.append("absent from proc view")
        if not process.listed_by_ps:
            reasons.append("absent from ps listing")
        if not reasons:
            continue
        severity = (
            "critical"
            if not process.visible_in_proc and not process.listed_by_ps
            else "high"
        )
        detections.append(
            Detection(
                "KRN-PROC-001",
                severity,
                subject,
                "hidden process indicators: " + ", ".join(reasons),
            )
        )

    ordered = tuple(
        sorted(
            detections,
            key=lambda detection: (
                -SEVERITY_ORDER[detection.severity],
                detection.rule_id,
                detection.subject,
                detection.message,
            ),
        )
    )
    return DetectionReport(ordered)


def _meets_threshold(detection: Detection, threshold: str) -> bool:
    return SEVERITY_ORDER[detection.severity] >= SEVERITY_ORDER[threshold]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a synthetic syscall snapshot without kernel access."
    )
    parser.add_argument("snapshot", type=Path, help="path to the JSON snapshot")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--fail-on",
        choices=("none", *SEVERITY_ORDER),
        default="none",
        help="exit 1 when a detection of this severity or higher exists",
    )
    args = parser.parse_args(argv)

    try:
        snapshot = parse_snapshot(load_snapshot(args.snapshot))
        report = analyze_snapshot(snapshot)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.format_text())

    if args.fail_on != "none" and any(
        _meets_threshold(detection, args.fail_on)
        for detection in report.detections
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
