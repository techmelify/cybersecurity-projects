#!/usr/bin/env python3
"""Offline SBOM/dependency snapshot analyzer.

Reads a local snapshot and reports policy findings. It performs no network
access, package resolution, or installation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "Component",
    "Policy",
    "Finding",
    "Analysis",
    "load_components",
    "analyze",
    "render",
    "main",
]

DEFAULT_TRUSTED_PUBLISHERS = frozenset({"Acme Security", "Internal Build", "PyPI", "npm Registry"})
DEFAULT_RESTRICTED_LICENSES = frozenset({"gpl-3.0", "agpl-3.0", "sspl-1.0", "busl-1.1"})
MISSING_VALUES = {"", "none", "unknown", "n/a", "unattested", "unlicensed", "null"}
WEAK_ALGORITHMS = {"md5", "sha1", "sha224"}
HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Component:
    name: str
    version: str = ""
    publisher: str = ""
    license: str = ""
    hashes: tuple[str, ...] = ()
    provenance: str = ""


@dataclass(frozen=True)
class Policy:
    trusted_publishers: frozenset[str] = DEFAULT_TRUSTED_PUBLISHERS
    restricted_licenses: frozenset[str] = DEFAULT_RESTRICTED_LICENSES
    require_provenance: bool = True


@dataclass(frozen=True)
class Finding:
    category: str  # provenance-gap | weak-integrity | unusual-publisher | license-risk
    severity: str
    component: str
    detail: str


@dataclass(frozen=True)
class Analysis:
    findings: tuple[Finding, ...]
    component_count: int


def load_components(data: Mapping[str, object] | Iterable[Mapping[str, object]]) -> tuple[Component, ...]:
    items = data.get("components", []) if isinstance(data, Mapping) else data
    components: list[Component] = []
    for item in items:
        hashes = item.get("hashes", ())
        if isinstance(hashes, str):
            hashes = (hashes,)
        components.append(
            Component(
                name=str(item["name"]),
                version=str(item.get("version", "")),
                publisher=str(item.get("publisher", "")),
                license=str(item.get("license", "")),
                hashes=tuple(str(value) for value in hashes),
                provenance=str(item.get("provenance", item.get("attestation", ""))),
            )
        )
    return tuple(components)


def _weak_hash_details(hashes: tuple[str, ...]) -> list[str]:
    problems: list[str] = []
    if not hashes:
        return ["no integrity hash recorded"]
    for value in hashes:
        algorithm, separator, digest = value.partition(":")
        algorithm = algorithm.strip().lower()
        if not separator or algorithm not in HEX_LENGTHS:
            problems.append(f"unrecognized hash format '{value}'")
            continue
        if algorithm in WEAK_ALGORITHMS:
            problems.append(f"weak hash algorithm {algorithm}")
        elif not re.fullmatch(r"[0-9a-f]+", digest.strip().lower()) or len(digest.strip()) != HEX_LENGTHS[algorithm]:
            problems.append(f"malformed {algorithm} digest")
    return problems


def analyze(components: Iterable[Component], policy: Policy = Policy()) -> Analysis:
    components = tuple(components)
    trusted = {name.casefold() for name in policy.trusted_publishers}
    restricted = {name.casefold() for name in policy.restricted_licenses}
    findings: list[Finding] = []

    for component in components:
        provenance = component.provenance.strip().lower()
        if policy.require_provenance and provenance in MISSING_VALUES:
            findings.append(
                Finding(
                    "provenance-gap",
                    "high",
                    component.name,
                    "no build provenance attestation recorded",
                )
            )

        for problem in _weak_hash_details(component.hashes):
            findings.append(Finding("weak-integrity", "high", component.name, problem))

        publisher = component.publisher.strip()
        if publisher.casefold() in MISSING_VALUES:
            findings.append(Finding("unusual-publisher", "medium", component.name, "publisher is missing"))
        elif publisher.casefold() not in trusted:
            severity = "high" if "unknown" in publisher.casefold() or "anonymous" in publisher.casefold() else "medium"
            findings.append(
                Finding(
                    "unusual-publisher",
                    severity,
                    component.name,
                    f"publisher '{publisher}' is not in the trusted allowlist",
                )
            )

        license_name = component.license.strip().lower()
        if license_name in MISSING_VALUES:
            findings.append(Finding("license-risk", "medium", component.name, "license is missing or unknown"))
        elif license_name in restricted:
            findings.append(
                Finding("license-risk", "high", component.name, f"restricted license {component.license}")
            )

    findings.sort(key=lambda item: (SEVERITY_RANK.get(item.severity, 9), item.category, item.component, item.detail))
    return Analysis(findings=tuple(findings), component_count=len(components))


def render(analysis: Analysis) -> str:
    lines = [
        "=== SUPPLY CHAIN REVIEW ===",
        f"Components: {analysis.component_count} | Findings: {len(analysis.findings)}",
    ]
    for finding in analysis.findings:
        lines.append(f"[{finding.severity}] {finding.category} {finding.component}")
        lines.append(f"    {finding.detail}")
    if not analysis.findings:
        lines.append("No policy findings in this snapshot.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze a local SBOM/dependency snapshot for policy gaps.")
    parser.add_argument("snapshot", type=Path, help="JSON component list or {'components': [...]}")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument(
        "--trusted-publisher",
        action="append",
        default=[],
        help="replace the default publisher allowlist (repeatable)",
    )
    parser.add_argument(
        "--restricted-license",
        action="append",
        default=[],
        help="replace the default restricted license list (repeatable)",
    )
    parser.add_argument(
        "--allow-missing-provenance",
        action="store_true",
        help="do not flag components without provenance attestations",
    )
    args = parser.parse_args(argv)

    policy = Policy(
        trusted_publishers=frozenset(args.trusted_publisher) if args.trusted_publisher else DEFAULT_TRUSTED_PUBLISHERS,
        restricted_licenses=frozenset(args.restricted_license) if args.restricted_license else DEFAULT_RESTRICTED_LICENSES,
        require_provenance=not args.allow_missing_provenance,
    )
    try:
        components = load_components(json.loads(args.snapshot.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    analysis = analyze(components, policy)
    if args.json:
        print(
            json.dumps(
                [finding.__dict__ for finding in analysis.findings],
                indent=2,
            )
        )
    else:
        print(render(analysis))
    return 0


if __name__ == "__main__":
    sys.exit(main())
