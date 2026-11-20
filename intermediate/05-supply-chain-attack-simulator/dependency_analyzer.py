#!/usr/bin/env python3
"""Risk analysis of a synthetic dependency graph.

This is a defensive substitution for a supply-chain attack simulator. It reads
a local graph description and flags suspicious naming, stale packages, and
unexpected maintainers. It never downloads, builds, publishes, or executes a
package.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Iterable

__all__ = [
    "Package",
    "Dependency",
    "Graph",
    "Risk",
    "Analysis",
    "edit_distance",
    "typosquat_candidates",
    "analyze_graph",
    "load_graph",
    "format_analysis",
]

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}
SEVERITY_POINTS = {"high": 20, "medium": 10, "low": 5}


@dataclass(frozen=True)
class Package:
    name: str
    version: str = "1.0.0"
    maintainers: tuple[str, ...] = ()
    last_release_days: int | None = None


@dataclass(frozen=True)
class Dependency:
    source: str
    target: str
    kind: str = "runtime"


@dataclass(frozen=True)
class Graph:
    packages: tuple[Package, ...]
    dependencies: tuple[Dependency, ...]
    known_names: tuple[str, ...] = ()
    trusted_maintainers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Risk:
    package: str
    rule: str
    severity: str
    detail: str


@dataclass(frozen=True)
class Analysis:
    risks: tuple[Risk, ...]
    counts: dict[str, int]
    score: int


def edit_distance(left: str, right: str) -> int:
    """Levenshtein distance using a rolling row (O(min) memory)."""
    previous = list(range(len(right) + 1))
    for row_index, left_char in enumerate(left, 1):
        current = [row_index]
        for column_index, right_char in enumerate(right, 1):
            substitution = previous[column_index - 1] + (left_char != right_char)
            current.append(
                min(
                    previous[column_index] + 1,
                    current[column_index - 1] + 1,
                    substitution,
                )
            )
        previous = current
    return previous[-1]


def typosquat_candidates(
    name: str,
    known_names: Iterable[str],
    *,
    min_length: int = 4,
) -> tuple[str, ...]:
    """Return known names suspiciously close to ``name``.

    A one-character edit or high character-similarity ratio is enough to be
    flagged. Results are sorted so callers get stable output.
    """
    target = name.strip().lower()
    if len(target) < min_length:
        return ()
    matches: set[str] = set()
    for raw in known_names:
        candidate = raw.strip()
        normalised = candidate.lower()
        if not normalised or normalised == target:
            continue
        distance = edit_distance(target, normalised)
        ratio = SequenceMatcher(None, target, normalised).ratio()
        if distance == 1 or ratio >= 0.86:
            matches.add(candidate)
    return tuple(sorted(matches))


def analyze_graph(
    graph: Graph,
    *,
    stale_days: int = 365,
    min_name_length: int = 4,
) -> Analysis:
    """Evaluate packages and dependencies against the lab risk rules."""
    if stale_days < 0:
        raise ValueError("stale_days must not be negative")
    if min_name_length < 1:
        raise ValueError("min_name_length must be at least 1")

    trusted = {name.strip().lower() for name in graph.trusted_maintainers if name.strip()}
    risks: list[Risk] = []

    for package in sorted(graph.packages, key=lambda item: item.name.lower()):
        candidates = typosquat_candidates(
            package.name, graph.known_names, min_length=min_name_length
        )
        if candidates:
            risks.append(
                Risk(package.name, "typosquat_like", "high",
                     f"similar to known name(s): {', '.join(candidates)}")
            )

        if package.last_release_days is not None and package.last_release_days >= stale_days:
            risks.append(
                Risk(package.name, "unmaintained", "medium",
                     f"{package.last_release_days} days since last release (limit {stale_days})")
            )

        if trusted:
            unexpected = sorted(
                maintainer for maintainer in package.maintainers
                if maintainer.strip().lower() not in trusted
            )
            if unexpected:
                risks.append(
                    Risk(package.name, "unexpected_maintainer", "high",
                         f"maintainer(s) outside trusted list: {', '.join(unexpected)}")
                )
            elif not package.maintainers:
                risks.append(
                    Risk(package.name, "unknown_maintainer", "low", "no maintainers listed")
                )

    known_packages = {package.name for package in graph.packages}
    for dependency in sorted(
        graph.dependencies, key=lambda item: (item.source, item.target, item.kind)
    ):
        if dependency.target not in known_packages:
            risks.append(
                Risk(dependency.source, "unknown_dependency", "medium",
                     f"depends on unlisted package {dependency.target!r}")
            )

    risks.sort(
        key=lambda risk: (
            -SEVERITY_RANK.get(risk.severity, 0),
            risk.rule,
            risk.package.lower(),
            risk.detail,
        )
    )
    raw_counts: dict[str, int] = {}
    for risk in risks:
        raw_counts[risk.rule] = raw_counts.get(risk.rule, 0) + 1
    counts = {key: raw_counts[key] for key in sorted(raw_counts, key=lambda k: (-raw_counts[k], k))}
    score = min(100, sum(SEVERITY_POINTS[risk.severity] for risk in risks))
    return Analysis(tuple(risks), counts, score)


def _as_strings(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return tuple(item.strip() for item in value if item.strip())


def load_graph(path: Path) -> Graph:
    """Load a synthetic graph description from a local JSON file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid graph JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("graph must be a JSON object")

    packages: list[Package] = []
    for index, raw in enumerate(data.get("packages", []), 1):
        if not isinstance(raw, dict):
            raise ValueError(f"package {index} must be an object")
        name = str(raw.get("name", "")).strip()
        if not name:
            raise ValueError(f"package {index} has no name")
        days = raw.get("last_release_days")
        if days is not None and (isinstance(days, bool) or not isinstance(days, int) or days < 0):
            raise ValueError(f"package {index} has invalid last_release_days")
        packages.append(
            Package(
                name=name,
                version=str(raw.get("version", "1.0.0")),
                maintainers=_as_strings(raw.get("maintainers"), "maintainers"),
                last_release_days=days,
            )
        )

    dependencies: list[Dependency] = []
    for index, raw in enumerate(data.get("dependencies", []), 1):
        if not isinstance(raw, dict):
            raise ValueError(f"dependency {index} must be an object")
        source = str(raw.get("source", "")).strip()
        target = str(raw.get("target", "")).strip()
        if not source or not target:
            raise ValueError(f"dependency {index} needs source and target")
        dependencies.append(
            Dependency(source, target, str(raw.get("kind", "runtime")).strip() or "runtime")
        )

    return Graph(
        packages=tuple(packages),
        dependencies=tuple(dependencies),
        known_names=_as_strings(data.get("known_names"), "known_names"),
        trusted_maintainers=_as_strings(data.get("trusted_maintainers"), "trusted_maintainers"),
    )


def format_analysis(analysis: Analysis) -> str:
    lines = [f"Supply-chain graph risk score: {analysis.score}/100", "Counts:"]
    if analysis.counts:
        lines.extend(f"  {rule}: {count}" for rule, count in analysis.counts.items())
    else:
        lines.append("  none")
    lines.append("Risks:")
    if analysis.risks:
        for risk in analysis.risks:
            lines.append(f"  [{risk.severity.upper():6}] {risk.rule} ({risk.package}): {risk.detail}")
    else:
        lines.append("  none")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse a synthetic dependency graph for risk.")
    parser.add_argument("--graph", type=Path, required=True, help="local graph JSON file")
    parser.add_argument("--stale-days", type=int, default=365, help="staleness threshold (default: 365)")
    parser.add_argument("--min-name-length", type=int, default=4, help="minimum typo-check length")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        analysis = analyze_graph(
            load_graph(args.graph),
            stale_days=args.stale_days,
            min_name_length=args.min_name_length,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(asdict(analysis), indent=2))
    else:
        print(format_analysis(analysis))
    return 0


if __name__ == "__main__":
    sys.exit(main())
