#!/usr/bin/env python3
"""Defensive scoring of synthetic packet timing and size logs.

The tool looks for three patterns often associated with covert channels:
unusually regular inter-arrival times, a low-cardinality size alphabet, and
small bursts separated by long quiet periods. It is analysis-only: there is no
sender, encoder, socket, or live capture.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "PacketEvent",
    "Signal",
    "ChannelAssessment",
    "parse_events",
    "assess",
    "demo_logs",
]


@dataclass(frozen=True)
class PacketEvent:
    """One synthetic observation with a relative timestamp in seconds."""

    timestamp: float
    size: int
    source: str = "synthetic"
    destination: str = "synthetic"


@dataclass(frozen=True)
class Signal:
    """A scored heuristic with a human-readable explanation."""

    name: str
    score: int
    detail: str


@dataclass(frozen=True)
class ChannelAssessment:
    """Deterministic assessment of one log."""

    signals: tuple[Signal, ...]
    score: int
    verdict: str
    events_analyzed: int


def parse_events(data: Iterable[Mapping[str, object]]) -> tuple[PacketEvent, ...]:
    """Read ``timestamp``/``t`` and ``size``/``bytes`` records."""
    events: list[PacketEvent] = []
    for record in data:
        raw_time = record.get("timestamp", record.get("t"))
        raw_size = record.get("size", record.get("bytes"))
        if raw_time is None or raw_size is None:
            raise ValueError("each event needs a timestamp and a size")
        event = PacketEvent(
            float(raw_time),  # type: ignore[arg-type]
            int(raw_size),  # type: ignore[arg-type]
            str(record.get("source", "synthetic")),
            str(record.get("destination", "synthetic")),
        )
        if event.size <= 0:
            raise ValueError("packet size must be positive")
        if events and event.timestamp < events[-1].timestamp:
            raise ValueError("event timestamps must be non-decreasing")
        events.append(event)
    return tuple(events)


def _gaps(events: tuple[PacketEvent, ...]) -> list[float]:
    return [round(second.timestamp - first.timestamp, 6) for first, second in zip(events, events[1:])]


def _regular_timing(events: tuple[PacketEvent, ...]) -> Signal | None:
    gaps = _gaps(events)
    if len(gaps) < 4:
        return None
    mean_gap = statistics.fmean(gaps)
    if mean_gap <= 0:
        return None
    deviation = statistics.fmean(abs(gap - mean_gap) for gap in gaps)
    ratio = deviation / mean_gap
    if ratio <= 0.05:
        score = 3
    elif ratio <= 0.15:
        score = 2
    else:
        return None
    return Signal("regular-timing", score, f"{len(gaps)} gaps, mean-dev/mean={ratio:.3f}")


def _size_encoding(events: tuple[PacketEvent, ...]) -> Signal | None:
    if len(events) < 8:
        return None
    counts = Counter(event.size for event in events)
    distinct = len(counts)
    if not 2 <= distinct <= 6:
        return None
    total = len(events)
    coverage = sum(count for _, count in counts.most_common(4)) / total
    if coverage < 0.9:
        return None
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )
    if entropy > 1.6:
        return None
    return Signal(
        "size-encoding",
        2,
        f"{distinct} recurring sizes, entropy={entropy:.2f} bits",
    )


def _low_rate_bursts(events: tuple[PacketEvent, ...]) -> Signal | None:
    if len(events) < 6:
        return None
    clusters: list[list[PacketEvent]] = [[events[0]]]
    for event in events[1:]:
        if event.timestamp - clusters[-1][-1].timestamp <= 0.5:
            clusters[-1].append(event)
        else:
            clusters.append([event])
    if len(clusters) < 3:
        return None

    intra_gaps = [gap for cluster in clusters for gap in _gaps(tuple(cluster))]
    quiet_gaps = [
        clusters[index + 1][0].timestamp - clusters[index][-1].timestamp
        for index in range(len(clusters) - 1)
    ]
    if not intra_gaps or not quiet_gaps:
        return None
    if min(quiet_gaps) >= 5.0 and statistics.median(intra_gaps) <= 1.0:
        return Signal(
            "low-rate-bursts",
            2,
            f"{len(clusters)} clusters, minimum quiet gap={min(quiet_gaps):.1f}s",
        )
    return None


def assess(events: tuple[PacketEvent, ...]) -> ChannelAssessment:
    """Score a synthetic log. Pure and offline."""
    signals = tuple(
        sorted(
            (signal for detector in (_regular_timing, _size_encoding, _low_rate_bursts)
             if (signal := detector(events)) is not None),
            key=lambda item: item.name,
        )
    )
    score = sum(signal.score for signal in signals)
    if score >= 5:
        verdict = "likely-covert"
    elif score >= 2:
        verdict = "suspicious"
    else:
        verdict = "benign"
    return ChannelAssessment(signals, score, verdict, len(events))


def demo_logs() -> dict[str, tuple[PacketEvent, ...]]:
    """Return two synthetic logs for documentation and CLI demonstration."""
    benign = tuple(
        PacketEvent(index * (0.5 if index % 2 else 1.5), 200 + index * 17)
        for index in range(12)
    )
    suspicious = tuple(
        PacketEvent(float(index), 100 if index % 2 == 0 else 101)
        for index in range(12)
    )
    return {"benign": benign, "covert-pattern": suspicious}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score a synthetic packet log for covert-channel patterns.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="JSON list of packet events")
    source.add_argument("--demo", action="store_true", help="score built-in synthetic examples")
    args = parser.parse_args(argv)
    try:
        if args.demo:
            results = {
                name: asdict(assess(events)) for name, events in demo_logs().items()
            }
        else:
            data = json.loads(args.file.read_text(encoding="utf-8"))
            results = asdict(assess(parse_events(data)))
    except (ValueError, OSError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
