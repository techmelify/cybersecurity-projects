#!/usr/bin/env python3
"""Local CLI finding tracker with CVSS-like scoring and status workflow.

FastAPI/React are replaced by argparse and a JSON file. There is no web UI,
no HTTP server, and no network access. Scores are CVSS-like teaching scores,
not official CVSS v3.1 base scores.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

__all__ = [
    "CvssVector",
    "Finding",
    "Tracker",
    "cvss_like_score",
    "severity_for_score",
    "can_transition",
    "transition",
    "ALLOWED_TRANSITIONS",
    "main",
]

_FORMAT = "bug-bounty-lab-v1"
_AV = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20}
_AC = {"low": 0.77, "high": 0.44}
_PR_UNCHANGED = {"none": 0.85, "low": 0.62, "high": 0.27}
_PR_CHANGED = {"none": 0.85, "low": 0.68, "high": 0.50}
_UI = {"none": 0.85, "required": 0.62}
_CIA = {"none": 0.0, "low": 0.22, "high": 0.56}

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"triaged", "wont_fix"}),
    "triaged": frozenset({"in_progress", "wont_fix", "open"}),
    "in_progress": frozenset({"fixed", "open"}),
    "fixed": frozenset({"closed", "open"}),
    "closed": frozenset({"open"}),
    "wont_fix": frozenset({"open"}),
}


@dataclass(frozen=True)
class CvssVector:
    """The eight inputs used by the simplified base-score formula."""

    attack_vector: str = "network"
    attack_complexity: str = "low"
    privileges_required: str = "none"
    user_interaction: str = "none"
    scope: str = "unchanged"
    confidentiality: str = "low"
    integrity: str = "low"
    availability: str = "none"

    def __post_init__(self) -> None:
        choices = {
            "attack_vector": _AV,
            "attack_complexity": _AC,
            "privileges_required": _PR_UNCHANGED,
            "user_interaction": _UI,
            "scope": {"unchanged": 1, "changed": 1},
            "confidentiality": _CIA,
            "integrity": _CIA,
            "availability": _CIA,
        }
        for name, allowed in choices.items():
            if getattr(self, name) not in allowed:
                raise ValueError(f"invalid value for {name}: {getattr(self, name)!r}")

    def to_dict(self) -> dict[str, str]:
        return {
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "scope": self.scope,
            "confidentiality": self.confidentiality,
            "integrity": self.integrity,
            "availability": self.availability,
        }


@dataclass(frozen=True)
class Finding:
    """One tracked security finding."""

    finding_id: str
    title: str
    target: str
    description: str
    vector: CvssVector
    status: str = "open"

    def __post_init__(self) -> None:
        if not self.finding_id or not self.title or not self.target:
            raise ValueError("finding_id, title, and target must not be empty")
        if self.status not in ALLOWED_TRANSITIONS:
            raise ValueError(f"unknown status: {self.status!r}")

    @property
    def score(self) -> float:
        return cvss_like_score(self.vector)

    @property
    def severity(self) -> str:
        return severity_for_score(self.score)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "target": self.target,
            "description": self.description,
            "vector": self.vector.to_dict(),
            "status": self.status,
            "score": self.score,
            "severity": self.severity,
        }


def cvss_like_score(vector: CvssVector) -> float:
    """Compute a bounded teaching score inspired by CVSS v3.1 base metrics."""
    c, i, a = (_CIA[vector.confidentiality], _CIA[vector.integrity], _CIA[vector.availability])
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if vector.scope == "unchanged":
        impact = 6.42 * iss
        pr = _PR_UNCHANGED[vector.privileges_required]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        pr = _PR_CHANGED[vector.privileges_required]
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * _AV[vector.attack_vector] * _AC[vector.attack_complexity] * pr * _UI[vector.user_interaction]
    raw = min(impact + exploitability, 10.0) if vector.scope == "unchanged" else min(1.08 * (impact + exploitability), 10.0)
    return math.ceil(raw * 10) / 10


def severity_for_score(score: float) -> str:
    """Map a 0.0-10.0 score onto a severity label."""
    if not 0.0 <= score <= 10.0:
        raise ValueError("score must be between 0 and 10")
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def can_transition(current: str, new: str) -> bool:
    """Return whether a status change is permitted."""
    if current not in ALLOWED_TRANSITIONS or new not in ALLOWED_TRANSITIONS:
        return False
    return new in ALLOWED_TRANSITIONS[current]


def transition(finding: Finding, new_status: str) -> Finding:
    """Return a copy of a finding with a validated new status."""
    if not can_transition(finding.status, new_status):
        raise ValueError(f"invalid status transition: {finding.status} -> {new_status}")
    return Finding(
        finding.finding_id,
        finding.title,
        finding.target,
        finding.description,
        finding.vector,
        new_status,
    )


def _vector_from_dict(raw: dict[str, str]) -> CvssVector:
    return CvssVector(**{name: str(raw[name]) for name in CvssVector().to_dict()})


def _finding_from_dict(raw: dict[str, object]) -> Finding:
    return Finding(
        str(raw["finding_id"]),
        str(raw["title"]),
        str(raw["target"]),
        str(raw.get("description", "")),
        _vector_from_dict(raw["vector"]),
        str(raw.get("status", "open")),
    )


class Tracker:
    """A JSON-backed collection of findings with atomic saves."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._findings: dict[str, Finding] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("tracker file is missing or invalid JSON") from exc
        if not isinstance(document, dict) or document.get("format") != _FORMAT:
            raise ValueError("unsupported tracker format")
        raw_findings = document.get("findings")
        if not isinstance(raw_findings, list):
            raise ValueError("tracker findings must be a list")
        loaded: dict[str, Finding] = {}
        for raw in raw_findings:
            finding = _finding_from_dict(raw)
            if finding.finding_id in loaded:
                raise ValueError(f"duplicate finding id: {finding.finding_id}")
            loaded[finding.finding_id] = finding
        self._findings = loaded

    def _save(self) -> None:
        document = {
            "format": _FORMAT,
            "findings": [finding.to_dict() for finding in self.list_findings()],
        }
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        os.replace(temp, self.path)

    def add(self, finding: Finding) -> None:
        if finding.finding_id in self._findings:
            raise ValueError(f"finding already exists: {finding.finding_id}")
        self._findings[finding.finding_id] = finding
        self._save()

    def get(self, finding_id: str) -> Finding:
        try:
            return self._findings[finding_id]
        except KeyError as exc:
            raise KeyError(f"finding not found: {finding_id}") from exc

    def list_findings(self) -> tuple[Finding, ...]:
        return tuple(sorted(self._findings.values(), key=lambda item: item.finding_id))

    def set_status(self, finding_id: str, new_status: str) -> Finding:
        updated = transition(self.get(finding_id), new_status)
        self._findings[finding_id] = updated
        self._save()
        return updated

    def export(self, path: Path) -> dict[str, object]:
        findings = self.list_findings()
        report = {
            "format": _FORMAT,
            "total": len(findings),
            "by_severity": {
                severity: sum(1 for finding in findings if finding.severity == severity)
                for severity in ("critical", "high", "medium", "low", "none")
            },
            "findings": [finding.to_dict() for finding in findings],
        }
        Path(path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report


def _vector_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--av", dest="attack_vector", default="network", choices=sorted(_AV))
    parser.add_argument("--ac", dest="attack_complexity", default="low", choices=sorted(_AC))
    parser.add_argument("--pr", dest="privileges_required", default="none", choices=sorted(_PR_UNCHANGED))
    parser.add_argument("--ui", dest="user_interaction", default="none", choices=sorted(_UI))
    parser.add_argument("--scope", default="unchanged", choices=["unchanged", "changed"])
    parser.add_argument("--c", dest="confidentiality", default="low", choices=sorted(_CIA))
    parser.add_argument("--i", dest="integrity", default="low", choices=sorted(_CIA))
    parser.add_argument("--a", dest="availability", default="none", choices=sorted(_CIA))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("store", type=Path, help="local JSON finding store")
    sub = parser.add_subparsers(dest="command", required=True)

    add_p = sub.add_parser("add", help="add a finding")
    add_p.add_argument("finding_id")
    add_p.add_argument("title")
    add_p.add_argument("target")
    add_p.add_argument("--description", default="")
    _vector_flags(add_p)

    status_p = sub.add_parser("status", help="move a finding through the workflow")
    status_p.add_argument("finding_id")
    status_p.add_argument("new_status", choices=sorted(ALLOWED_TRANSITIONS))

    list_p = sub.add_parser("list", help="list findings")
    list_p.add_argument("--json", action="store_true")

    export_p = sub.add_parser("export", help="write a JSON report")
    export_p.add_argument("output", type=Path)

    args = parser.parse_args(argv)
    try:
        tracker = Tracker(args.store)
        if args.command == "add":
            vector = CvssVector(
                args.attack_vector,
                args.attack_complexity,
                args.privileges_required,
                args.user_interaction,
                args.scope,
                args.confidentiality,
                args.integrity,
                args.availability,
            )
            finding = Finding(args.finding_id, args.title, args.target, args.description, vector)
            tracker.add(finding)
            print(f"added {finding.finding_id}: {finding.score:.1f} ({finding.severity})")
            return 0

        if args.command == "status":
            updated = tracker.set_status(args.finding_id, args.new_status)
            print(f"{updated.finding_id}: {updated.status}")
            return 0

        findings: Sequence[Finding] = tracker.list_findings()
        if args.command == "export":
            report = tracker.export(args.output)
            print(f"exported {report['total']} finding(s) to {args.output}")
            return 0

        if args.json:
            print(json.dumps({"findings": [finding.to_dict() for finding in findings]}, indent=2))
        else:
            for finding in findings:
                print(f"{finding.finding_id} [{finding.severity} {finding.score:.1f}] {finding.status}: {finding.title} @ {finding.target}")
            if not findings:
                print("no findings")
        return 0
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
