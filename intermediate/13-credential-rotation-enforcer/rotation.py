#!/usr/bin/env python3
"""Check a synthetic credential snapshot against a rotation-age policy.

Python substitution of the Crystal-based upstream tool. This module only
evaluates the JSON snapshot supplied by the caller; it never contacts a real
credential store, vault, directory, or network service.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "Credential",
    "Policy",
    "Finding",
    "age_days",
    "check_rotation",
    "load_snapshot",
]


@dataclass(frozen=True)
class Credential:
    """One entry in a synthetic credential inventory."""

    service: str
    last_rotated: str  # ISO-8601 calendar date, e.g. "2026-01-15"
    owner: str


@dataclass(frozen=True)
class Policy:
    """Maximum permitted age, in days, for a rotated secret."""

    max_age_days: int


@dataclass(frozen=True)
class Finding:
    """A credential whose age exceeds the configured maximum."""

    service: str
    owner: str
    last_rotated: str
    age_days: int
    overdue_by_days: int
    severity: str


def age_days(credential: Credential, as_of: date) -> int:
    """Return whole days elapsed since ``credential.last_rotated``.

    Negative values indicate a rotation date in the future relative to
    ``as_of``; they are left untouched so callers can spot clock skew.
    """
    rotated = date.fromisoformat(credential.last_rotated)
    return (as_of - rotated).days


def check_rotation(
    credentials: Iterable[Credential],
    policy: Policy,
    as_of: date,
) -> list[Finding]:
    """Return overdue credentials in input order.

    Severity is ``high`` once a secret has been stale for more than twice the
    policy window, and ``medium`` otherwise. ``as_of`` is explicit so results
    are deterministic and testable.
    """
    findings: list[Finding] = []
    for credential in credentials:
        age = age_days(credential, as_of)
        if age <= policy.max_age_days:
            continue
        overdue_by = age - policy.max_age_days
        severity = "high" if overdue_by > policy.max_age_days else "medium"
        findings.append(
            Finding(
                service=credential.service,
                owner=credential.owner,
                last_rotated=credential.last_rotated,
                age_days=age,
                overdue_by_days=overdue_by,
                severity=severity,
            )
        )
    return findings


def load_snapshot(data: Mapping[str, object]) -> tuple[Policy, list[Credential]]:
    """Parse ``{"policy": {...}, "credentials": [...]}`` into domain objects."""
    policy_data = data["policy"]
    if not isinstance(policy_data, Mapping):
        raise TypeError("policy must be an object")
    policy = Policy(int(policy_data["max_age_days"]))

    raw_credentials = data.get("credentials", [])
    if not isinstance(raw_credentials, list):
        raise TypeError("credentials must be a list")
    credentials = [
        Credential(
            str(item["service"]),
            str(item["last_rotated"]),
            str(item["owner"]),
        )
        for item in raw_credentials
    ]
    return policy, credentials


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report credentials that are older than the rotation policy."
    )
    parser.add_argument("snapshot", type=Path, help="JSON credential snapshot")
    parser.add_argument(
        "--as-of",
        default=None,
        help="ISO-8601 date used as 'today' (defaults to the current date)",
    )
    parser.add_argument("--max-age", type=int, default=None, help="override policy max_age_days")
    args = parser.parse_args(argv)

    try:
        policy, credentials = load_snapshot(
            json.loads(args.snapshot.read_text(encoding="utf-8"))
        )
        if args.max_age is not None:
            policy = Policy(args.max_age)
        as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
        findings = check_rotation(credentials, policy, as_of)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for finding in findings:
        print(
            f"[{finding.severity.upper():6}] {finding.service} owner={finding.owner} "
            f"age={finding.age_days}d overdue_by={finding.overdue_by_days}d"
        )
    print(f"{len(findings)} overdue credential(s) as of {as_of.isoformat()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
