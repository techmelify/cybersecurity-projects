#!/usr/bin/env python3
"""Detect username enumeration signals in recorded login results.

DEFENSIVE SUBSTITUTION: this tool analyzes an already-recorded dataset. It
never sends a login request, never holds a credential, and does not connect to
an authentication service.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "DetectorConfig",
    "LoginResult",
    "UserSignature",
    "EnumerationFinding",
    "EnumerationReport",
    "normalize_message",
    "build_signatures",
    "analyze",
    "load_results",
    "main",
]


@dataclass(frozen=True)
class DetectorConfig:
    """Thresholds for the three enumeration signals."""

    min_observations: int = 2
    min_users: int = 2
    timing_ratio: float = 1.5
    timing_delta_ms: float = 20.0
    failure_outcomes: tuple[str, ...] = ("failure", "invalid", "locked")


@dataclass(frozen=True)
class LoginResult:
    """One recorded authentication attempt (no password is stored)."""

    username: str
    outcome: str
    status_code: int
    message: str
    duration_ms: float


@dataclass(frozen=True)
class UserSignature:
    """Aggregated failure behavior for one username."""

    username: str
    observations: int
    status_codes: tuple[int, ...]
    messages: tuple[str, ...]
    median_ms: float


@dataclass(frozen=True)
class EnumerationFinding:
    """A measurable difference between usernames on failed logins."""

    kind: str
    severity: str
    detail: str
    evidence: tuple[str, ...]

    @property
    def message(self) -> str:
        return f"{self.kind} ({self.severity}): {self.detail}"


@dataclass(frozen=True)
class EnumerationReport:
    """Aggregate analysis of a login-result dataset."""

    findings: tuple[EnumerationFinding, ...]
    signatures: tuple[UserSignature, ...]
    total_results: int

    @property
    def vulnerable(self) -> bool:
        return bool(self.findings)


def normalize_message(message: str) -> str:
    """Lowercase and collapse whitespace for stable message comparison."""

    return " ".join(message.strip().lower().split())


def build_signatures(
    results: Iterable[LoginResult], config: DetectorConfig | None = None
) -> tuple[UserSignature, ...]:
    """Aggregate failed-login behavior per username."""

    settings = config or DetectorConfig()
    failures = {outcome.lower() for outcome in settings.failure_outcomes}
    grouped: dict[str, list[LoginResult]] = {}
    for result in results:
        if result.outcome.lower() in failures:
            grouped.setdefault(result.username, []).append(result)

    signatures: list[UserSignature] = []
    for username, entries in sorted(grouped.items()):
        if len(entries) < settings.min_observations:
            continue
        signatures.append(
            UserSignature(
                username,
                len(entries),
                tuple(sorted({entry.status_code for entry in entries})),
                tuple(sorted({normalize_message(entry.message) for entry in entries})),
                statistics.median(entry.duration_ms for entry in entries),
            )
        )
    return tuple(signatures)


def analyze(
    results: Iterable[LoginResult], config: DetectorConfig | None = None
) -> EnumerationReport:
    """Compare failure signatures across usernames."""

    settings = config or DetectorConfig()
    all_results = tuple(results)
    signatures = build_signatures(all_results, settings)
    findings: list[EnumerationFinding] = []

    if len(signatures) >= settings.min_users:
        all_codes = {code for signature in signatures for code in signature.status_codes}
        if len(all_codes) > 1:
            findings.append(
                EnumerationFinding(
                    "status_code_differential",
                    "high",
                    "failed logins return different status codes for different usernames",
                    tuple(f"{s.username}={list(s.status_codes)}" for s in signatures),
                )
            )

        all_messages = {message for signature in signatures for message in signature.messages}
        if len(all_messages) > 1:
            findings.append(
                EnumerationFinding(
                    "message_differential",
                    "high",
                    "failed logins return different messages for different usernames",
                    tuple(f"{s.username}={list(s.messages)}" for s in signatures),
                )
            )

        ordered = sorted(signatures, key=lambda signature: signature.median_ms)
        split = len(ordered) // 2
        fast, slow = ordered[:split], ordered[split:]
        if fast and slow:
            fast_median = statistics.median(s.median_ms for s in fast)
            slow_median = statistics.median(s.median_ms for s in slow)
            delta = slow_median - fast_median
            ratio = slow_median / fast_median if fast_median > 0 else float("inf")
            if delta >= settings.timing_delta_ms and ratio >= settings.timing_ratio:
                findings.append(
                    EnumerationFinding(
                        "timing_differential",
                        "medium",
                        f"failure response times differ by {delta:.1f} ms ({ratio:.2f}x)",
                        (
                            "fast=" + ",".join(s.username for s in fast),
                            "slow=" + ",".join(s.username for s in slow),
                        ),
                    )
                )

    return EnumerationReport(tuple(findings), signatures, len(all_results))


def load_results(document: Any) -> tuple[LoginResult, ...]:
    """Validate and convert a JSON-like list of result records."""

    if not isinstance(document, list):
        raise ValueError("expected a list of login results")
    results: list[LoginResult] = []
    for index, record in enumerate(document):
        if not isinstance(record, Mapping):
            raise ValueError(f"record {index} is not an object")
        try:
            results.append(
                LoginResult(
                    str(record["username"]),
                    str(record["outcome"]),
                    int(record["status_code"]),
                    str(record["message"]),
                    float(record["duration_ms"]),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"record {index} is missing or has invalid fields") from exc
    return tuple(results)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect username enumeration signals in recorded login results."
    )
    parser.add_argument("results", help="local JSON file of recorded login results")
    parser.add_argument("--json", action="store_true", help="emit JSON findings")
    parser.add_argument("--strict", action="store_true", help="exit 1 when a signal is found")
    args = parser.parse_args(argv)

    from pathlib import Path

    try:
        document = json.loads(Path(args.results).read_text(encoding="utf-8"))
        results = load_results(document)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(f"cannot read results: {exc}")
        return 2

    report = analyze(results)
    if args.json:
        print(
            json.dumps(
                {
                    "findings": [asdict(f) for f in report.findings],
                    "signatures": [asdict(s) for s in report.signatures],
                    "total_results": report.total_results,
                },
                indent=2,
            )
        )
    else:
        for finding in report.findings:
            print(finding.message)
            for item in finding.evidence:
                print(f"  - {item}")
        print(f"{len(report.findings)} signal(s) from {report.total_results} result(s)")
    return 1 if args.strict and report.vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
