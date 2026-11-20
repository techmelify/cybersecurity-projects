#!/usr/bin/env python3
"""Offline beacon timing simulator and detector.

The upstream "simple C2 beacon" is reimplemented as a lab-only timing model:
no sockets, no callbacks, no host control. It generates synthetic event times
and detects the regular intervals that beacons tend to produce.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

__all__ = ["BeaconPattern", "generate_beacons", "detect_beacons"]


@dataclass(frozen=True)
class BeaconPattern:
    events: int
    interval_seconds: float | None
    regularity: float
    suspicious: bool

    @property
    def message(self) -> str:
        if self.interval_seconds is None:
            return "not enough events"
        return (
            f"{self.events} events, interval≈{self.interval_seconds:.1f}s, "
            f"regularity={self.regularity:.2f}"
            + (" SUSPICIOUS" if self.suspicious else "")
        )


def generate_beacons(
    count: int,
    interval: float = 60.0,
    jitter: float = 0.2,
    start: datetime | None = None,
    seed: int = 7,
) -> list[datetime]:
    """Return synthetic event times with bounded random jitter."""
    if count < 1 or interval <= 0 or jitter < 0:
        raise ValueError("invalid simulation parameters")
    rng = random.Random(seed)
    now = start or datetime(2026, 11, 20, tzinfo=timezone.utc)
    times = [now]
    for _ in range(count - 1):
        factor = 1 + rng.uniform(-jitter, jitter)
        times.append(times[-1] + timedelta(seconds=interval * factor))
    return times


def detect_beacons(times: Iterable[datetime], tolerance: float = 0.25) -> BeaconPattern:
    """Score how regular the gaps between events are."""
    ordered = sorted(times)
    if len(ordered) < 3:
        return BeaconPattern(len(ordered), None, 0.0, False)
    gaps = [(b - a).total_seconds() for a, b in zip(ordered, ordered[1:])]
    gaps = [g for g in gaps if g > 0]
    if len(gaps) < 2:
        return BeaconPattern(len(ordered), None, 0.0, False)
    median = statistics.median(gaps)
    mad = statistics.median([abs(g - median) for g in gaps])
    regularity = max(0.0, 1 - mad / median) if median else 0.0
    suspicious = len(gaps) >= 4 and regularity >= (1 - tolerance)
    return BeaconPattern(len(ordered), median, regularity, suspicious)


def _load_times(path: Path) -> list[datetime]:
    return [datetime.fromisoformat(line.strip()) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulate and detect beacon-like timing.")
    sub = parser.add_subparsers(dest="command", required=True)
    sim = sub.add_parser("simulate", help="emit synthetic event times as JSON")
    sim.add_argument("-n", "--count", type=int, default=10)
    sim.add_argument("--interval", type=float, default=60.0)
    sim.add_argument("--jitter", type=float, default=0.2)
    sim.add_argument("--seed", type=int, default=7)
    det = sub.add_parser("detect", help="score event times from a file")
    det.add_argument("file", type=Path)
    det.add_argument("--tolerance", type=float, default=0.25)
    args = parser.parse_args(argv)

    if args.command == "simulate":
        times = generate_beacons(args.count, args.interval, args.jitter, seed=args.seed)
        print(json.dumps([t.isoformat() for t in times], indent=2))
        return 0

    try:
        result = detect_beacons(_load_times(args.file), args.tolerance)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
