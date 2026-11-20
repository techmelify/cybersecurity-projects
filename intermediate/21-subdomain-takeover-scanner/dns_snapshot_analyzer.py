#!/usr/bin/env python3
"""Analyze a DNS snapshot for dangling CNAMEs and takeover-prone providers.

This is a read-only, offline analyzer. It never resolves DNS, opens sockets, or
contacts a provider; "dangling" state comes from the supplied snapshot only.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "CnameRecord",
    "TakeoverService",
    "Snapshot",
    "Finding",
    "normalize_dns",
    "parse_snapshot",
    "match_provider",
    "audit",
    "main",
]


@dataclass(frozen=True)
class CnameRecord:
    host: str
    target: str


@dataclass(frozen=True)
class TakeoverService:
    provider: str
    domains: tuple[str, ...]
    note: str


@dataclass(frozen=True)
class Snapshot:
    records: tuple[CnameRecord, ...]
    services: tuple[TakeoverService, ...]
    dangling_targets: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    id: str
    host: str
    severity: str  # low | medium | high
    detail: str
    recommendation: str


def normalize_dns(value: str) -> str:
    return value.strip().rstrip(".").lower()


def parse_snapshot(data: Mapping[str, Any]) -> Snapshot:
    records = tuple(
        CnameRecord(normalize_dns(str(item["host"])), normalize_dns(str(item["target"])))
        for item in data.get("cname_records", [])
    )
    services = tuple(
        TakeoverService(
            provider=str(item["provider"]),
            domains=tuple(normalize_dns(str(domain)) for domain in item.get("domains", [])),
            note=str(item.get("note", "")),
        )
        for item in data.get("known_services", [])
    )
    dangling = tuple(normalize_dns(str(target)) for target in data.get("dangling_targets", []))
    return Snapshot(records, services, dangling)


def match_provider(target: str, services: tuple[TakeoverService, ...]) -> TakeoverService | None:
    """Return the service with the most specific matching provider domain."""
    normalized = normalize_dns(target)
    candidates: list[tuple[int, str, TakeoverService]] = []
    for service in services:
        for domain in service.domains:
            if normalized == domain or normalized.endswith("." + domain):
                candidates.append((len(domain), service.provider, service))
    if not candidates:
        return None
    candidates.sort(key=lambda entry: (-entry[0], entry[1]))
    return candidates[0][2]


def audit(snapshot: Snapshot) -> list[Finding]:
    """Audit the snapshot and return deterministic findings."""
    findings: list[Finding] = []
    dangling = set(snapshot.dangling_targets)

    for record in sorted(snapshot.records, key=lambda item: (item.host, item.target)):
        if record.target in dangling:
            findings.append(
                Finding(
                    "DNS-001",
                    record.host,
                    "high",
                    f"CNAME target {record.target} is marked dangling in the snapshot",
                    "Remove the stale CNAME or point it at a resource you control.",
                )
            )

        service = match_provider(record.target, snapshot.services)
        if service is None:
            continue

        note = f" {service.note}" if service.note else ""
        findings.append(
            Finding(
                "DNS-002",
                record.host,
                "medium",
                f"CNAME target {record.target} matches known provider {service.provider}.{note}",
                "Verify custom-domain configuration and remove unused provider bindings.",
            )
        )
        if record.target in service.domains:
            findings.append(
                Finding(
                    "DNS-003",
                    record.host,
                    "high",
                    f"CNAME target is the bare provider domain {record.target}",
                    "Use a fully qualified tenant-specific target instead of a provider apex.",
                )
            )

    unique = {(finding.id, finding.host, finding.detail): finding for finding in findings}
    return [unique[key] for key in sorted(unique)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit a DNS snapshot for dangling CNAMEs and takeover-prone providers."
    )
    parser.add_argument("snapshot", type=Path, help="JSON DNS snapshot")
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
                f"[{finding.severity.upper():6}] {finding.id} {finding.host}: "
                f"{finding.detail} -> {finding.recommendation}"
            )
        print(f"findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
