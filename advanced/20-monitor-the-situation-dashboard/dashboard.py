#!/usr/bin/env python3
"""Console dashboard aggregating synthetic security event feeds (offline)."""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "Event",
    "Bucket",
    "Report",
    "load_events",
    "generate_sample_events",
    "summarize",
    "render",
    "main",
]

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SOURCES = ("ids-edge-01", "auth-gateway", "endpoint-agent", "dns-resolver", "backup-job")
CATEGORIES = ("auth", "network", "endpoint", "dns", "system")
MESSAGES = ("threshold crossed", "policy matched", "anomaly scored", "state changed")


@dataclass(frozen=True)
class Event:
    timestamp: str
    source: str
    severity: str
    category: str
    message: str


@dataclass(frozen=True)
class Bucket:
    start: str
    count: int


@dataclass(frozen=True)
class Report:
    total: int
    severity_counts: tuple[tuple[str, int], ...]
    top_sources: tuple[tuple[str, int], ...]
    timeline: tuple[Bucket, ...]
    bucket_minutes: int = 15

    @property
    def elevated(self) -> int:
        return sum(count for severity, count in self.severity_counts if severity in {"critical", "high"})


def _parse_timestamp(text: str) -> datetime:
    parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _bucket_start(moment: datetime, minutes: int) -> datetime:
    minute_of_day = moment.hour * 60 + moment.minute
    floored = (minute_of_day // minutes) * minutes
    return moment.replace(hour=floored // 60, minute=floored % 60, second=0, microsecond=0)


def load_events(data: Mapping[str, object] | Iterable[Mapping[str, object]]) -> tuple[Event, ...]:
    items = data.get("events", []) if isinstance(data, Mapping) else data
    return tuple(
        Event(
            str(item["timestamp"]),
            str(item["source"]),
            str(item["severity"]),
            str(item.get("category", "general")),
            str(item.get("message", "")),
        )
        for item in items
    )


def generate_sample_events(count: int = 48, seed: int = 7) -> tuple[Event, ...]:
    """Build a reproducible synthetic feed; no live data sources are used."""

    rng = random.Random(seed)
    base = datetime(2026, 1, 12, 8, 0, 0)
    events: list[Event] = []
    for index in range(count):
        source = rng.choice(SOURCES)
        severity = rng.choice(SEVERITIES)
        category = rng.choice(CATEGORIES)
        moment = base + timedelta(minutes=index * 3 + rng.randrange(0, 2), seconds=rng.randrange(0, 60))
        events.append(
            Event(
                moment.isoformat(timespec="seconds"),
                source,
                severity,
                category,
                f"{rng.choice(MESSAGES)} #{index:03d}",
            )
        )
    return tuple(events)


def summarize(
    events: Iterable[Event],
    top_n: int = 5,
    bucket_minutes: int = 15,
) -> Report:
    """Aggregate events into deterministic severity/source/timeline views."""

    if top_n < 1:
        raise ValueError("top_n must be positive")
    if bucket_minutes < 1:
        raise ValueError("bucket_minutes must be positive")

    events = tuple(events)
    severity_counter = Counter(event.severity.strip().lower() for event in events)
    severity_counts = [(name, severity_counter.pop(name)) for name in SEVERITY_ORDER if severity_counter[name]]
    severity_counts.extend(sorted(severity_counter.items(), key=lambda pair: (-pair[1], pair[0])))

    source_counter = Counter(event.source for event in events)
    top_sources = sorted(source_counter.items(), key=lambda pair: (-pair[1], pair[0]))[:top_n]

    timeline: tuple[Bucket, ...] = ()
    if events:
        starts = [_bucket_start(_parse_timestamp(event.timestamp), bucket_minutes) for event in events]
        bucket_counter = Counter(start.isoformat(timespec="seconds") for start in starts)
        cursor, last = min(starts), max(starts)
        step = timedelta(minutes=bucket_minutes)
        timeline_items: list[Bucket] = []
        while cursor <= last:
            key = cursor.isoformat(timespec="seconds")
            timeline_items.append(Bucket(key, bucket_counter.get(key, 0)))
            cursor += step
        timeline = tuple(timeline_items)

    return Report(
        total=len(events),
        severity_counts=tuple(severity_counts),
        top_sources=tuple(top_sources),
        timeline=timeline,
        bucket_minutes=bucket_minutes,
    )


def render(report: Report, bar_width: int = 20) -> str:
    lines = [
        "=== SITUATION DASHBOARD ===",
        f"Events: {report.total} | Elevated (critical/high): {report.elevated}",
        "",
        "Severity:",
    ]
    if report.severity_counts:
        peak = max(count for _, count in report.severity_counts)
        for name, count in report.severity_counts:
            bar = "#" * max(1, round(count / peak * bar_width))
            lines.append(f"  {name:<9} {bar:<{bar_width}} {count}")
    else:
        lines.append("  (none)")

    lines.extend(["", "Top sources:"])
    if report.top_sources:
        peak = max(count for _, count in report.top_sources)
        for rank, (source, count) in enumerate(report.top_sources, start=1):
            bar = "#" * max(1, round(count / peak * bar_width))
            lines.append(f"  {rank}. {source:<16} {bar:<{bar_width}} {count}")
    else:
        lines.append("  (none)")

    lines.extend(["", f"Timeline ({report.bucket_minutes}m buckets):"])
    if report.timeline:
        peak = max(bucket.count for bucket in report.timeline)
        for bucket in report.timeline:
            label = datetime.fromisoformat(bucket.start).strftime("%H:%M")
            bar = "#" * max(1, round(bucket.count / peak * bar_width)) if bucket.count else ""
            lines.append(f"  {label}  {bar:<{bar_width}} {bucket.count}")
    else:
        lines.append("  (none)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a console dashboard from a synthetic event feed.")
    parser.add_argument("feed", type=Path, nargs="?", help="JSON event list or {'events': [...]}")
    parser.add_argument("--sample", action="store_true", help="use the built-in deterministic sample feed")
    parser.add_argument("--top", type=int, default=5)
    parser.add_argument("--bucket-minutes", type=int, default=15)
    args = parser.parse_args(argv)

    if args.sample == (args.feed is not None):
        parser.error("provide either a feed file or --sample")
    try:
        if args.sample:
            events = generate_sample_events()
        else:
            events = load_events(json.loads(args.feed.read_text(encoding="utf-8")))
        report = summarize(events, top_n=args.top, bucket_minutes=args.bucket_minutes)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
