#!/usr/bin/env python3
"""SIEM dashboard as a local CLI: correlate synthetic JSONL events.

This is a Python substitution for the upstream Flask/React web dashboard.
There is no web server, no browser, and no live data source.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

__all__ = [
    "Event",
    "Alert",
    "Dashboard",
    "parse_event",
    "parse_events",
    "load_events",
    "correlate",
    "format_dashboard",
]

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
HIGH_SEVERITIES = frozenset({"high", "critical"})


@dataclass(frozen=True)
class Event:
    timestamp: datetime | None
    event_type: str
    source_ip: str
    user: str
    host: str
    severity: str
    message: str


@dataclass(frozen=True)
class Alert:
    rule: str
    detail: str
    severity: str
    count: int


@dataclass(frozen=True)
class Dashboard:
    total: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_source: dict[str, int]
    top_sources: tuple[tuple[str, int], ...]
    alerts: tuple[Alert, ...]


def _text(value: object, default: str) -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _timestamp(value: object, line_number: int) -> datetime | None:
    if value is None or value == "":
        return None
    raw = str(value).strip()
    iso_text = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError as exc:
        raise ValueError(f"line {line_number}: invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_event(line: str, *, line_number: int = 0) -> Event:
    """Parse one JSONL record into an Event with safe defaults."""
    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"line {line_number}: invalid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")

    return Event(
        timestamp=_timestamp(raw.get("timestamp", raw.get("time")), line_number),
        event_type=_text(raw.get("event_type", raw.get("type")), "unknown").lower(),
        source_ip=_text(raw.get("source_ip", raw.get("ip")), "unknown"),
        user=_text(raw.get("user"), "unknown"),
        host=_text(raw.get("host"), "unknown"),
        severity=_text(raw.get("severity"), "info").lower(),
        message=_text(raw.get("message"), ""),
    )


def parse_events(lines: Iterable[str]) -> list[Event]:
    events: list[Event] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        events.append(parse_event(line, line_number=number))
    return events


def load_events(path: Path) -> list[Event]:
    return parse_events(path.read_text(encoding="utf-8").splitlines())


def _counts(values: Iterable[str]) -> dict[str, int]:
    counter = Counter(values)
    return {key: count for key, count in sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))}


def correlate(events: Iterable[Event], *, threshold: int = 5) -> Dashboard:
    """Aggregate events and emit rule-based alerts.

    All rules use only event fields; no wall-clock time is read.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    records = list(events)
    by_type = _counts(event.event_type for event in records)
    by_severity = _counts(event.severity for event in records)
    by_source = _counts(event.source_ip for event in records)
    source_items = list(by_source.items())
    top_sources = tuple(source_items[:5])

    failures: list[Event] = [event for event in records if event.event_type == "failed_login"]
    failures_by_ip = Counter(event.source_ip for event in failures)

    alerts: list[Alert] = []
    for source_ip, count in sorted(failures_by_ip.items(), key=lambda pair: (-pair[1], pair[0])):
        if count >= threshold:
            alerts.append(
                Alert("failed_login_burst", f"{source_ip}: {count} failed logins", "high", count)
            )

    high_count = sum(1 for event in records if event.severity in HIGH_SEVERITIES)
    if high_count:
        alerts.append(
            Alert("high_severity_events", f"{high_count} high/critical events", "high", high_count)
        )

    off_hours = [
        event for event in records
        if event.timestamp is not None and (event.timestamp.hour < 6 or event.timestamp.hour >= 22)
    ]
    if len(off_hours) >= threshold:
        alerts.append(
            Alert("off_hours_activity", f"{len(off_hours)} events between 22:00 and 06:00",
                  "medium", len(off_hours))
        )

    failed_users = {event.user for event in failures if event.user != "unknown"}
    if len(failed_users) >= threshold:
        alerts.append(
            Alert("many_failed_users", f"{len(failed_users)} distinct users with failed logins",
                  "medium", len(failed_users))
        )

    blocks = sum(1 for event in records if event.event_type == "firewall_block")
    if blocks >= threshold:
        alerts.append(
            Alert("firewall_block_burst", f"{blocks} firewall blocks", "low", blocks)
        )

    alerts.sort(key=lambda alert: (-SEVERITY_RANK.get(alert.severity, 0), alert.rule, alert.detail))
    return Dashboard(len(records), by_type, by_severity, by_source, top_sources, tuple(alerts))


def format_dashboard(dashboard: Dashboard) -> str:
    lines = [
        "SIEM Dashboard (synthetic events)",
        f"Total events: {dashboard.total}",
        "By type:",
    ]
    if dashboard.by_type:
        lines.extend(f"  {key}: {count}" for key, count in dashboard.by_type.items())
    else:
        lines.append("  none")
    lines.append("By severity:")
    if dashboard.by_severity:
        lines.extend(f"  {key}: {count}" for key, count in dashboard.by_severity.items())
    else:
        lines.append("  none")
    lines.append("Top source IPs:")
    if dashboard.top_sources:
        lines.extend(f"  {key}: {count}" for key, count in dashboard.top_sources)
    else:
        lines.append("  none")
    lines.append("Alerts:")
    if dashboard.alerts:
        for alert in dashboard.alerts:
            lines.append(f"  [{alert.severity.upper():8}] {alert.rule}: {alert.detail}")
    else:
        lines.append("  none")
    return "\n".join(lines)


def _dashboard_dict(dashboard: Dashboard) -> dict[str, object]:
    payload: dict[str, object] = asdict(dashboard)
    payload["alerts"] = [asdict(alert) for alert in dashboard.alerts]
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Correlate synthetic JSONL security events.")
    parser.add_argument("events", type=Path, help="path to a JSONL event log")
    parser.add_argument("--threshold", type=int, default=5, help="alert threshold (default: 5)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        dashboard = correlate(load_events(args.events), threshold=args.threshold)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(_dashboard_dict(dashboard), indent=2))
    else:
        print(format_dashboard(dashboard))
    return 0


if __name__ == "__main__":
    sys.exit(main())
