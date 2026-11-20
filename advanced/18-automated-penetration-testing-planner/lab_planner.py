#!/usr/bin/env python3
"""Authorisation-aware planning for an isolated security lab.

Given a JSON scope of owned assets and explicitly authorised tests, this tool
produces an ordered checklist plan. Out-of-scope targets, production assets,
and unauthorised test ids are refused. It executes nothing: no command runner,
no scanner, no socket, and no target contact.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

__all__ = [
    "Asset",
    "AuthorisedTest",
    "Scope",
    "PlanStep",
    "Refusal",
    "Plan",
    "load_scope",
    "build_plan",
]

_PRODUCTION_ENVIRONMENTS = frozenset({"production", "prod", "live"})
_PRODUCTION_NAME_TOKENS = ("prod", "production", "live")

_RULES_OF_ENGAGEMENT: tuple[str, ...] = (
    "Written authorisation must be on file before any test activity.",
    "Only owned lab or staging assets declared in scope may be examined.",
    "No exploitation, payload delivery, credential guessing, or production traffic is permitted.",
    "Stop on instability, preserve notes offline, and report every observation.",
)

_CHECKLISTS: dict[str, tuple[str, ...]] = {
    "recon": (
        "Confirm written authorisation and the asset owner.",
        "List only in-scope hosts, ports, and services from local records.",
        "Record each observation with its source and timestamp.",
    ),
    "configuration-review": (
        "Export the configuration read-only from the lab asset.",
        "Compare settings against the agreed hardening baseline.",
        "Document deviations without changing the system.",
    ),
    "vulnerability-scan": (
        "Use safe, non-intrusive checks only.",
        "Exclude denial-of-service and intrusive plugins.",
        "Review every finding manually before recording it.",
    ),
    "credential-audit": (
        "Use only synthetic lab accounts supplied for the exercise.",
        "Never test production or personal accounts.",
        "Rotate any lab credentials touched during the exercise.",
    ),
}
_GENERIC_CHECKLIST: tuple[str, ...] = (
    "Confirm written authorisation for this exact test and asset.",
    "Perform the review read-only inside the lab.",
    "Capture evidence offline and summarise the result.",
)


@dataclass(frozen=True)
class Asset:
    """An owned lab or staging asset."""

    name: str
    network: str
    owner: str
    environment: str = "lab"


@dataclass(frozen=True)
class AuthorisedTest:
    """One explicitly permitted, non-intrusive test."""

    id: str
    title: str
    category: str
    asset: str


@dataclass(frozen=True)
class Scope:
    """Parsed scope document."""

    assets: tuple[Asset, ...]
    tests: tuple[AuthorisedTest, ...]


@dataclass(frozen=True)
class PlanStep:
    """A single ordered checklist item mapped to an authorised test."""

    order: int
    test_id: str
    title: str
    asset: str
    category: str
    checklist: tuple[str, ...]


@dataclass(frozen=True)
class Refusal:
    """A target or test that must not proceed."""

    target: str
    reason: str


@dataclass(frozen=True)
class Plan:
    """Final defensive plan with refusals and rules of engagement."""

    steps: tuple[PlanStep, ...]
    refusals: tuple[Refusal, ...]
    rules_of_engagement: tuple[str, ...]


def _is_production(asset: Asset) -> bool:
    environment = asset.environment.strip().lower()
    name = asset.name.lower()
    return environment in _PRODUCTION_ENVIRONMENTS or any(
        token in name for token in _PRODUCTION_NAME_TOKENS
    )


def load_scope(data: Mapping[str, object]) -> Scope:
    """Validate and parse a scope mapping. Pure function."""
    raw_assets = data.get("assets", [])
    raw_tests = data.get("tests", [])
    if not isinstance(raw_assets, list) or not isinstance(raw_tests, list):
        raise ValueError("assets and tests must be lists")

    assets: list[Asset] = []
    for record in raw_assets:
        if not isinstance(record, Mapping):
            raise ValueError("each asset must be an object")
        name = str(record.get("name", "")).strip()
        if not name:
            raise ValueError("asset name is required")
        assets.append(
            Asset(
                name,
                str(record.get("network", "")).strip(),
                str(record.get("owner", "")).strip(),
                str(record.get("environment", "lab")).strip(),
            )
        )
    if len({asset.name for asset in assets}) != len(assets):
        raise ValueError("duplicate asset names")

    tests: list[AuthorisedTest] = []
    for record in raw_tests:
        if not isinstance(record, Mapping):
            raise ValueError("each test must be an object")
        identifier = str(record.get("id", "")).strip()
        title = str(record.get("title", "")).strip()
        category = str(record.get("category", "")).strip().lower()
        asset = str(record.get("asset", "")).strip()
        if not identifier or not title or not category or not asset:
            raise ValueError("test id, title, category, and asset are required")
        tests.append(AuthorisedTest(identifier, title, category, asset))
    if len({test.id for test in tests}) != len(tests):
        raise ValueError("duplicate test ids")
    return Scope(tuple(assets), tuple(tests))


def _unique_refusals(items: Iterable[Refusal]) -> tuple[Refusal, ...]:
    seen: set[tuple[str, str]] = set()
    result: list[Refusal] = []
    for item in items:
        key = (item.target, item.reason)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return tuple(result)


def build_plan(
    scope: Scope,
    requested_tests: Sequence[str] | None = None,
    targets: Sequence[str] | None = None,
) -> Plan:
    """Build a checklist plan without executing anything."""
    assets = {asset.name: asset for asset in scope.assets}
    requested = tuple(dict.fromkeys(requested_tests)) if requested_tests is not None else None
    chosen_targets = tuple(dict.fromkeys(targets or ()))
    refusals: list[Refusal] = []

    allowed_targets: set[str] | None = None
    if chosen_targets:
        allowed_targets = set()
        for target in chosen_targets:
            asset = assets.get(target)
            if asset is None:
                refusals.append(Refusal(target, "out-of-scope: asset is not declared in the scope"))
            elif _is_production(asset):
                refusals.append(Refusal(target, "production target refused"))
            else:
                allowed_targets.add(target)

    steps: list[PlanStep] = []
    known_ids = {test.id for test in scope.tests}
    for test in scope.tests:
        if requested is not None and test.id not in requested:
            continue
        asset = assets.get(test.asset)
        if asset is None:
            refusals.append(Refusal(test.id, "test references an undeclared asset"))
            continue
        if _is_production(asset):
            refusals.append(Refusal(test.id, "test targets a production asset and is refused"))
            continue
        if allowed_targets is not None and test.asset not in allowed_targets:
            continue
        steps.append(
            PlanStep(
                order=len(steps) + 1,
                test_id=test.id,
                title=test.title,
                asset=test.asset,
                category=test.category,
                checklist=_CHECKLISTS.get(test.category, _GENERIC_CHECKLIST),
            )
        )

    if requested is not None:
        for identifier in requested:
            if identifier not in known_ids:
                refusals.append(Refusal(identifier, "unknown or unauthorised test id"))

    return Plan(
        tuple(steps),
        _unique_refusals(refusals),
        _RULES_OF_ENGAGEMENT,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan authorised lab tests; execute nothing.")
    parser.add_argument("--scope", type=Path, required=True, help="JSON scope document")
    parser.add_argument("--test", action="append", dest="tests", help="only this authorised test id")
    parser.add_argument("--target", action="append", dest="targets", help="limit the plan to this asset")
    parser.add_argument("--validate-only", action="store_true", help="report validity and refusals only")
    args = parser.parse_args(argv)
    try:
        scope = load_scope(json.loads(args.scope.read_text(encoding="utf-8")))
    except (ValueError, OSError, json.JSONDecodeError) as error:
        parser.error(str(error))
    plan = build_plan(scope, args.tests, args.targets)
    if args.validate_only:
        payload: dict[str, object] = {
            "valid": not plan.refusals,
            "steps": len(plan.steps),
            "refusals": [asdict(item) for item in plan.refusals],
        }
    else:
        payload = asdict(plan)
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
