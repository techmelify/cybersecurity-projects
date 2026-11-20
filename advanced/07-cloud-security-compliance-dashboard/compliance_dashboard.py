#!/usr/bin/env python3
"""Offline compliance dashboard for a synthetic cloud configuration snapshot.

The analyzer reads a JSON document that describes buckets, IAM policies,
volumes, and logging settings. It performs no API calls and never contacts a
cloud provider.
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
    "Finding",
    "ComplianceReport",
    "load_snapshot",
    "check_public_buckets",
    "check_over_permissive_iam",
    "check_unencrypted_volumes",
    "check_missing_logging",
    "evaluate_snapshot",
    "main",
]


@dataclass(frozen=True)
class Finding:
    """One compliance rule violation."""

    rule_id: str
    severity: str
    resource: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "resource": self.resource,
            "message": self.message,
        }


@dataclass(frozen=True)
class ComplianceReport:
    """Deterministically ordered findings from one snapshot."""

    findings: tuple[Finding, ...]

    def counts(self) -> dict[str, int]:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": len(self.findings),
            "counts": self.counts(),
            "findings": [finding.as_dict() for finding in self.findings],
        }

    def format_text(self) -> str:
        counts = self.counts()
        lines = [f"Cloud compliance findings: {len(self.findings)}"]
        lines.extend(
            f"  {level}: {counts[level]}"
            for level in reversed(tuple(SEVERITY_ORDER))
        )
        lines.append("")
        if not self.findings:
            lines.append("No findings in this synthetic snapshot.")
            return "\n".join(lines)
        for finding in self.findings:
            lines.append(
                f"[{finding.severity.upper()}] {finding.rule_id} "
                f"{finding.resource}: {finding.message}"
            )
        return "\n".join(lines)


def _objects(snapshot: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = snapshot.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a JSON array")
    result: list[Mapping[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"{key}[{index}] must be a JSON object")
        result.append(item)
    return result


def _as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [str(item) for item in value.values()]
    if isinstance(value, (list, tuple, set, frozenset)):
        result: list[str] = []
        for item in value:
            result.extend(_as_string_list(item))
        return result
    return [str(value)]


def _resource_name(obj: Mapping[str, Any], fallback: str) -> str:
    return str(obj.get("name") or obj.get("id") or fallback)


def load_snapshot(path: Path) -> Mapping[str, Any]:
    """Read a JSON snapshot from disk and validate its root type."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("snapshot root must be a JSON object")
    return data


def check_public_buckets(snapshot: Mapping[str, Any]) -> list[Finding]:
    """Flag buckets with public access flags or a disabled access block."""
    findings: list[Finding] = []
    for bucket in _objects(snapshot, "buckets"):
        name = _resource_name(bucket, "<unnamed-bucket>")
        acl = str(bucket.get("acl", "")).lower()
        raw_flags = [
            "public read" if bucket.get("public_read") is True else "",
            "public write" if bucket.get("public_write") is True else "",
            f"ACL {acl}" if acl in {"public-read", "public-read-write"} else "",
            (
                "public access block disabled"
                if bucket.get("public_access_block") is False
                else ""
            ),
        ]
        flags = list(dict.fromkeys(flag for flag in raw_flags if flag))
        if not flags:
            continue
        if any("write" in flag for flag in flags):
            severity = "critical"
        elif any("read" in flag for flag in flags):
            severity = "high"
        else:
            severity = "medium"
        findings.append(
            Finding(
                "CLOUD-S3-001",
                severity,
                name,
                "Public exposure indicators: " + ", ".join(flags),
            )
        )
    return findings


def check_over_permissive_iam(snapshot: Mapping[str, Any]) -> list[Finding]:
    """Flag Allow statements that grant wildcard actions on wildcard resources."""
    findings: list[Finding] = []
    for policy in _objects(snapshot, "iam_policies"):
        policy_name = _resource_name(policy, "<unnamed-policy>")
        statements_raw = policy.get("statements")
        if statements_raw is None:
            statements: list[Any] = [policy]
        elif isinstance(statements_raw, list):
            statements = statements_raw
        else:
            raise ValueError(f"statements in {policy_name} must be a JSON array")

        for index, statement in enumerate(statements):
            if not isinstance(statement, Mapping):
                raise ValueError(f"{policy_name}.statements[{index}] must be an object")
            if str(statement.get("effect", "Allow")).lower() != "allow":
                continue
            actions = [action.lower() for action in _as_string_list(statement.get("actions"))]
            resources = _as_string_list(statement.get("resources"))
            principals = [
                principal.lower()
                for principal in _as_string_list(statement.get("principal"))
            ]
            if not actions or not resources:
                continue
            has_wildcard_action = any(
                action == "*" or action.endswith(":*") for action in actions
            )
            has_wildcard_resource = any(resource == "*" for resource in resources)
            has_wildcard_principal = "*" in principals
            detail: str | None = None
            severity = "high"
            if has_wildcard_action and has_wildcard_resource:
                detail = "wildcard action on wildcard resource"
                if has_wildcard_principal:
                    severity = "critical"
            elif has_wildcard_action and has_wildcard_principal:
                detail = "wildcard action granted to wildcard principal"
            if detail is None:
                continue
            findings.append(
                Finding(
                    "CLOUD-IAM-001",
                    severity,
                    f"{policy_name}[{index}]",
                    f"Over-permissive IAM: {detail}",
                )
            )
    return findings


def check_unencrypted_volumes(snapshot: Mapping[str, Any]) -> list[Finding]:
    """Flag volumes that do not explicitly declare encryption enabled."""
    findings: list[Finding] = []
    for volume in _objects(snapshot, "volumes"):
        if volume.get("encrypted") is True:
            continue
        volume_id = _resource_name(volume, "<unnamed-volume>")
        findings.append(
            Finding(
                "CLOUD-EBS-001",
                "high",
                volume_id,
                "Volume does not declare encryption at rest",
            )
        )
    return findings


def check_missing_logging(snapshot: Mapping[str, Any]) -> list[Finding]:
    """Flag absent or disabled audit/flow/access logging controls."""
    logging_config = snapshot.get("logging", {})
    if logging_config is None:
        logging_config = {}
    if not isinstance(logging_config, Mapping):
        raise ValueError("logging must be a JSON object")
    checks = (
        ("cloudtrail_enabled", "CLOUD-LOG-001", "CloudTrail audit logging"),
        ("vpc_flow_logs_enabled", "CLOUD-LOG-002", "VPC flow logging"),
        ("s3_access_logging_enabled", "CLOUD-LOG-003", "S3 access logging"),
    )
    findings: list[Finding] = []
    for key, rule_id, label in checks:
        if logging_config.get(key) is True:
            continue
        findings.append(
            Finding(
                rule_id,
                "medium",
                "logging",
                f"{label} is missing or disabled",
            )
        )
    return findings


def evaluate_snapshot(snapshot: Mapping[str, Any]) -> ComplianceReport:
    """Run every rule and return findings sorted by severity, then identity."""
    findings = [
        *check_public_buckets(snapshot),
        *check_over_permissive_iam(snapshot),
        *check_unencrypted_volumes(snapshot),
        *check_missing_logging(snapshot),
    ]
    ordered = tuple(
        sorted(
            findings,
            key=lambda finding: (
                -SEVERITY_ORDER[finding.severity],
                finding.rule_id,
                finding.resource,
                finding.message,
            ),
        )
    )
    return ComplianceReport(ordered)


def _meets_threshold(finding: Finding, threshold: str) -> bool:
    return SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a synthetic cloud JSON snapshot without API calls."
    )
    parser.add_argument("snapshot", type=Path, help="path to the JSON snapshot")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--fail-on",
        choices=("none", *SEVERITY_ORDER),
        default="none",
        help="exit 1 when a finding of this severity or higher exists",
    )
    args = parser.parse_args(argv)

    try:
        snapshot = load_snapshot(args.snapshot)
        report = evaluate_snapshot(snapshot)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.format_text())

    if args.fail_on != "none" and any(
        _meets_threshold(finding, args.fail_on) for finding in report.findings
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
