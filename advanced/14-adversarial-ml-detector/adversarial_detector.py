#!/usr/bin/env python3
"""Defensive analysis of synthetic feature vectors.

The tool compares incoming vectors against a deterministic clean baseline and
rules them suspicious when they show outlier values, boundary saturation,
coordinated micro-perturbations, or batch-level distribution drift. It does
not train, modify, attack, or query any model.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

__all__ = [
    "FeatureVector",
    "Baseline",
    "Detection",
    "DriftSignal",
    "BatchReport",
    "build_baseline",
    "analyze_vector",
    "analyze_batch",
    "load_vectors",
]


@dataclass(frozen=True)
class FeatureVector:
    """One labelled synthetic observation."""

    identifier: str
    values: tuple[float, ...]


@dataclass(frozen=True)
class Baseline:
    """Per-feature statistics derived from known-benign vectors."""

    means: tuple[float, ...]
    stdevs: tuple[float, ...]
    lows: tuple[float, ...]
    highs: tuple[float, ...]
    size: int
    saturation_ratio: float

    @property
    def dimensions(self) -> int:
        return len(self.means)


@dataclass(frozen=True)
class Detection:
    """A rule hit for one incoming vector."""

    identifier: str
    signal: str
    detail: str
    score: int


@dataclass(frozen=True)
class DriftSignal:
    """Batch-level mean shift on a single feature."""

    feature: int
    baseline_mean: float
    batch_mean: float
    z_score: float


@dataclass(frozen=True)
class BatchReport:
    """Combined per-vector detections, drift, and a final verdict."""

    detections: tuple[Detection, ...]
    drift: tuple[DriftSignal, ...]
    score: int
    verdict: str


def _saturated(value: float) -> bool:
    return value <= 0.0 or value >= 1.0


def _check_dimensions(size: int, baseline: Baseline) -> None:
    if size != baseline.dimensions:
        raise ValueError(f"expected {baseline.dimensions} features, got {size}")


def load_vectors(data: Iterable[Mapping[str, object]]) -> tuple[FeatureVector, ...]:
    """Read ``identifier``/``values`` (or ``id``/``features``) records."""
    vectors: list[FeatureVector] = []
    for record in data:
        identifier = record.get("identifier", record.get("id"))
        raw = record.get("values", record.get("features"))
        if identifier is None or raw is None:
            raise ValueError("each vector needs an identifier and values")
        values = tuple(float(item) for item in raw)  # type: ignore[union-attr]
        if not values:
            raise ValueError("vectors must contain at least one feature")
        vectors.append(FeatureVector(str(identifier), values))
    return tuple(vectors)


def build_baseline(vectors: Sequence[FeatureVector]) -> Baseline:
    """Compute a deterministic baseline from known-benign vectors."""
    if not vectors:
        raise ValueError("baseline needs at least one vector")
    dimensions = len(vectors[0].values)
    if dimensions == 0:
        raise ValueError("vectors must contain at least one feature")
    if any(len(vector.values) != dimensions for vector in vectors):
        raise ValueError("all baseline vectors must have the same dimension")

    columns = [tuple(vector.values[index] for vector in vectors) for index in range(dimensions)]
    means = tuple(statistics.fmean(column) for column in columns)
    stdevs = tuple(statistics.pstdev(column) for column in columns)
    lows = tuple(min(column) for column in columns)
    highs = tuple(max(column) for column in columns)
    saturated = sum(1 for column in columns for value in column if _saturated(value))
    ratio = saturated / (len(vectors) * dimensions)
    return Baseline(means, stdevs, lows, highs, len(vectors), ratio)


def analyze_vector(
    vector: FeatureVector,
    baseline: Baseline,
    *,
    z_threshold: float = 3.0,
    epsilon: float = 0.15,
    saturation_limit: int = 3,
) -> tuple[Detection, ...]:
    """Flag suspicious patterns in a single vector. Pure function."""
    _check_dimensions(len(vector.values), baseline)
    findings: list[Detection] = []

    for index, value in enumerate(vector.values):
        stdev = baseline.stdevs[index]
        if stdev > 0.0:
            z_score = (value - baseline.means[index]) / stdev
            if abs(z_score) > z_threshold:
                findings.append(
                    Detection(
                        vector.identifier,
                        "z-score-outlier",
                        f"feature {index}: z={z_score:.2f}",
                        3,
                    )
                )
        margin = max(0.05, stdev)
        if value < baseline.lows[index] - margin or value > baseline.highs[index] + margin:
            findings.append(
                Detection(
                    vector.identifier,
                    "out-of-range-feature",
                    f"feature {index}: {value:.3f} outside observed range",
                    2,
                )
            )

    saturated_count = sum(1 for value in vector.values if _saturated(value))
    if saturated_count >= saturation_limit and baseline.saturation_ratio < 0.25:
        findings.append(
            Detection(
                vector.identifier,
                "saturated-features",
                f"{saturated_count} features pinned to 0 or 1",
                2,
            )
        )

    deltas = [value - mean for value, mean in zip(vector.values, baseline.means)]
    if len(deltas) >= 3 and all(0.0 < abs(delta) <= epsilon for delta in deltas):
        if all(delta > 0.0 for delta in deltas) or all(delta < 0.0 for delta in deltas):
            findings.append(
                Detection(
                    vector.identifier,
                    "coordinated-small-perturbation",
                    f"all {len(deltas)} features shifted by <= {epsilon} in one direction",
                    2,
                )
            )
    return tuple(sorted(findings, key=lambda item: (item.signal, item.detail)))


def analyze_batch(
    vectors: Sequence[FeatureVector],
    baseline: Baseline,
    *,
    z_threshold: float = 3.0,
    drift_threshold: float = 3.0,
    min_samples: int = 3,
) -> BatchReport:
    """Score a batch for per-vector anomalies and per-feature drift."""
    detections: list[Detection] = []
    for vector in vectors:
        detections.extend(analyze_vector(vector, baseline, z_threshold=z_threshold))

    drift: list[DriftSignal] = []
    if len(vectors) >= min_samples and baseline.size >= min_samples:
        for index in range(baseline.dimensions):
            stdev = baseline.stdevs[index]
            if stdev <= 0.0:
                continue
            batch_mean = statistics.fmean(vector.values[index] for vector in vectors)
            z_score = (batch_mean - baseline.means[index]) / (stdev / math.sqrt(len(vectors)))
            if abs(z_score) > drift_threshold:
                drift.append(
                    DriftSignal(index, baseline.means[index], batch_mean, z_score)
                )

    score = sum(item.score for item in detections) + 2 * len(drift)
    if score >= 6:
        verdict = "likely-adversarial"
    elif score >= 3:
        verdict = "suspicious"
    else:
        verdict = "benign"
    return BatchReport(tuple(detections), tuple(drift), score, verdict)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic vectors for suspicious patterns.")
    parser.add_argument("--baseline", type=Path, required=True, help="JSON list of benign vectors")
    parser.add_argument("--input", type=Path, required=True, help="JSON list of vectors to inspect")
    parser.add_argument("--z-threshold", type=float, default=3.0)
    args = parser.parse_args(argv)

    baseline = build_baseline(load_vectors(json.loads(args.baseline.read_text(encoding="utf-8"))))
    incoming = load_vectors(json.loads(args.input.read_text(encoding="utf-8")))
    report = analyze_batch(incoming, baseline, z_threshold=args.z_threshold)
    print(json.dumps(asdict(report), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
