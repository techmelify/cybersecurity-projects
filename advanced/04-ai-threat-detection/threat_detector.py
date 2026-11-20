#!/usr/bin/env python3
"""Transparent statistical anomaly detection over synthetic feature vectors.

No neural network, no PyTorch, no persisted model, and no training artifacts.
A baseline is computed in memory from synthetic normal vectors; each event is
scored with z-scores and a small set of readable rules.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

__all__ = [
    "Event",
    "Baseline",
    "Rule",
    "DetectorConfig",
    "Detection",
    "build_baseline",
    "default_rules",
    "score_event",
    "detect",
    "load_events",
    "load_rules",
    "demo_data",
    "detection_to_dict",
    "main",
]

_ZERO_DEVIATION_Z = 10.0


@dataclass(frozen=True)
class Event:
    """A synthetic event identified by explicit numeric features."""

    event_id: str
    features: dict[str, float]

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("event_id must not be empty")
        for name, value in self.features.items():
            if not math.isfinite(value):
                raise ValueError(f"feature {name!r} must be finite")


@dataclass(frozen=True)
class Baseline:
    """Per-feature means and population standard deviations."""

    means: dict[str, float]
    stddevs: dict[str, float]


@dataclass(frozen=True)
class Rule:
    """A simple threshold rule: trigger above and/or below given bounds."""

    name: str
    feature: str
    above: float | None = None
    below: float | None = None
    score: float = 2.0
    reason: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("rule name must not be empty")
        if self.above is None and self.below is None:
            raise ValueError("a rule needs an above or below threshold")
        if self.score < 0:
            raise ValueError("rule score must be non-negative")

    def matches(self, value: float) -> bool:
        return (self.above is not None and value > self.above) or (self.below is not None and value < self.below)

    def description(self) -> str:
        if self.reason:
            return self.reason
        bounds = []
        if self.above is not None:
            bounds.append(f"> {self.above:g}")
        if self.below is not None:
            bounds.append(f"< {self.below:g}")
        return f"{self.feature} {' or '.join(bounds)}"


@dataclass(frozen=True)
class DetectorConfig:
    """Z-score threshold and rule set used for all events."""

    z_threshold: float = 2.5
    rules: tuple[Rule, ...] = ()

    def __post_init__(self) -> None:
        if self.z_threshold <= 0:
            raise ValueError("z_threshold must be positive")


@dataclass(frozen=True)
class Detection:
    """The explainable result for one event."""

    event_id: str
    z_scores: dict[str, float]
    triggered_rules: tuple[str, ...]
    anomaly_score: float
    suspicious: bool
    reasons: tuple[str, ...]


def build_baseline(vectors: Sequence[Event]) -> Baseline:
    """Compute means and population stddevs in memory from normal vectors."""
    if len(vectors) < 2:
        raise ValueError("at least two baseline vectors are required")
    names = sorted(vectors[0].features)
    for event in vectors:
        if sorted(event.features) != names:
            raise ValueError("all baseline vectors must share the same feature names")

    means: dict[str, float] = {}
    stddevs: dict[str, float] = {}
    for name in names:
        values = [float(event.features[name]) for event in vectors]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        means[name] = mean
        stddevs[name] = math.sqrt(variance)
    return Baseline(means, stddevs)


def default_rules() -> tuple[Rule, ...]:
    return (
        Rule("many-failed-logins", "failed_logins", above=5, score=3, reason="failed_logins above 5"),
        Rule("large-egress", "bytes_out", above=500_000, score=2, reason="bytes_out above 500000"),
        Rule("admin-burst", "admin_actions", above=2, score=2, reason="admin_actions above 2"),
    )


def _z_score(value: float, mean: float, stddev: float) -> float:
    if stddev == 0:
        return 0.0 if abs(value - mean) < 1e-12 else _ZERO_DEVIATION_Z
    return (value - mean) / stddev


def score_event(event: Event, baseline: Baseline, config: DetectorConfig) -> Detection:
    """Score one event and explain every contribution to the decision."""
    for name in baseline.means:
        if name not in event.features:
            raise ValueError(f"event {event.event_id!r} is missing feature {name!r}")

    z_scores = {
        name: _z_score(float(event.features[name]), baseline.means[name], baseline.stddevs[name])
        for name in sorted(baseline.means)
    }
    reasons: list[str] = []
    triggered: list[str] = []
    rule_score = 0.0

    for rule in config.rules:
        if rule.feature not in event.features:
            raise ValueError(f"rule {rule.name!r} refers to missing feature {rule.feature!r}")
        value = float(event.features[rule.feature])
        if rule.matches(value):
            triggered.append(rule.name)
            rule_score += rule.score
            reasons.append(rule.description())

    peak_z = max((abs(value) for value in z_scores.values()), default=0.0)
    for name, value in z_scores.items():
        if abs(value) >= config.z_threshold:
            reasons.append(f"z_score({name})={value:.2f} exceeds {config.z_threshold:g}")

    anomaly_score = round(peak_z + rule_score, 6)
    suspicious = peak_z >= config.z_threshold or bool(triggered)
    return Detection(event.event_id, z_scores, tuple(triggered), anomaly_score, suspicious, tuple(reasons))


def detect(events: Sequence[Event], baseline: Baseline, config: DetectorConfig) -> tuple[Detection, ...]:
    """Score a batch while preserving input order."""
    return tuple(score_event(event, baseline, config) for event in events)


def _event_from_dict(raw: dict[str, object]) -> Event:
    features = raw.get("features")
    if not isinstance(features, dict):
        raise ValueError("each event needs a 'features' object")
    numeric = {str(name): float(value) for name, value in features.items()}
    return Event(str(raw["event_id"]), numeric)


def load_events(path: Path) -> tuple[Event, ...]:
    """Load synthetic events from a JSON list."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("events file must contain a JSON list")
    return tuple(_event_from_dict(item) for item in document)


def load_rules(path: Path) -> tuple[Rule, ...]:
    """Load optional rule definitions from a JSON list."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("rules file must contain a JSON list")
    return tuple(
        Rule(
            str(item["name"]),
            str(item["feature"]),
            item.get("above"),
            item.get("below"),
            float(item.get("score", 2.0)),
            str(item.get("reason", "")),
        )
        for item in document
    )


def demo_data() -> tuple[tuple[Event, ...], tuple[Event, ...]]:
    """Return deterministic synthetic baseline and evaluation events."""
    baseline = (
        Event("base-1", {"failed_logins": 1, "bytes_out": 1000.0, "admin_actions": 0}),
        Event("base-2", {"failed_logins": 2, "bytes_out": 2000.0, "admin_actions": 1}),
        Event("base-3", {"failed_logins": 1, "bytes_out": 1500.0, "admin_actions": 0}),
        Event("base-4", {"failed_logins": 2, "bytes_out": 1200.0, "admin_actions": 1}),
    )
    events = (
        Event("normal-1", {"failed_logins": 1, "bytes_out": 1400.0, "admin_actions": 0}),
        Event("spike-1", {"failed_logins": 9, "bytes_out": 900_000.0, "admin_actions": 3}),
    )
    return baseline, events


def detection_to_dict(detection: Detection) -> dict[str, object]:
    return {
        "event_id": detection.event_id,
        "z_scores": {name: round(value, 4) for name, value in detection.z_scores.items()},
        "triggered_rules": list(detection.triggered_rules),
        "anomaly_score": detection.anomaly_score,
        "suspicious": detection.suspicious,
        "reasons": list(detection.reasons),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path, help="JSON list of synthetic normal vectors")
    parser.add_argument("--events", type=Path, help="JSON list of events to score")
    parser.add_argument("--rules", type=Path, help="optional JSON list of simple rules")
    parser.add_argument("--z-threshold", type=float, default=2.5)
    parser.add_argument("--suspicious-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--demo", action="store_true", help="use built-in deterministic synthetic data")
    args = parser.parse_args(argv)

    try:
        if args.demo:
            if args.baseline or args.events:
                raise ValueError("--demo cannot be combined with --baseline/--events")
            baseline_events, events = demo_data()
        else:
            if not args.baseline or not args.events:
                raise ValueError("supply --baseline and --events, or use --demo")
            baseline_events, events = load_events(args.baseline), load_events(args.events)

        baseline = build_baseline(baseline_events)
        rules = load_rules(args.rules) if args.rules else default_rules()
        results = detect(events, baseline, DetectorConfig(args.z_threshold, rules))
    except (ValueError, OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    shown = tuple(result for result in results if result.suspicious) if args.suspicious_only else results
    suspicious_count = sum(1 for result in results if result.suspicious)

    if args.json:
        print(
            json.dumps(
                {
                    "baseline_features": sorted(baseline.means),
                    "total": len(results),
                    "suspicious": suspicious_count,
                    "detections": [detection_to_dict(result) for result in shown],
                },
                indent=2,
            )
        )
        return 0

    for result in shown:
        flag = "SUSPICIOUS" if result.suspicious else "normal"
        print(f"{result.event_id}: {flag} (score={result.anomaly_score:.2f})")
        for reason in result.reasons:
            print(f"  - {reason}")
    print(f"summary: {suspicious_count} suspicious of {len(results)} event(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
