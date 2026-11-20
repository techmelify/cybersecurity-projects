#!/usr/bin/env python3
"""Synthetic honeypot event generator and defensive analyzer.

No listener is started and no real credentials are generated or stored.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "HoneypotEvent",
    "Thresholds",
    "Finding",
    "Analysis",
    "load_events",
    "generate_events",
    "analyze",
    "render",
    "main",
]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class HoneypotEvent:
    timestamp: str
    source_ip: str
    service: str
    port: int
    event_type: str  # connect | auth_failure | auth_success
    username: str = ""  # synthetic label such as "user-003"
    credential_label: str = ""  # label such as "wordlist-a", never a secret


@dataclass(frozen=True)
class Thresholds:
    scan_ports: int = 5
    scan_window_seconds: int = 300
    stuffing_usernames: int = 5
    max_success_ratio: float = 0.2
    repeated_events: int = 8


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str
    source_ip: str
    detail: str
    count: int


@dataclass(frozen=True)
class Analysis:
    findings: tuple[Finding, ...]
    event_count: int
    source_count: int


def _parse_timestamp(text: str) -> datetime:
    parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def load_events(data: Mapping[str, object] | Iterable[Mapping[str, object]]) -> tuple[HoneypotEvent, ...]:
    items = data.get("events", []) if isinstance(data, Mapping) else data
    return tuple(
        HoneypotEvent(
            str(item["timestamp"]),
            str(item["source_ip"]),
            str(item["service"]),
            int(item["port"]),
            str(item["event_type"]),
            str(item.get("username", "")),
            str(item.get("credential_label", "")),
        )
        for item in items
    )


def generate_events(seed: int = 11, noise_events: int = 18) -> tuple[HoneypotEvent, ...]:
    """Create a deterministic simulated capture with three planted patterns."""

    rng = random.Random(seed)
    base = datetime(2026, 2, 3, 9, 0, 0)
    events: list[HoneypotEvent] = []

    # Pattern 1: a source touching many ports in a short window.
    scanner = "198.51.100.23"
    for offset, port in enumerate(range(4000, 4010)):
        events.append(
            HoneypotEvent(
                (base + timedelta(seconds=offset * 20)).isoformat(timespec="seconds"),
                scanner,
                "tcp-probe",
                port,
                "connect",
            )
        )

    # Pattern 2: many synthetic usernames, no successful authentication.
    stuffing = "203.0.113.44"
    for offset in range(8):
        events.append(
            HoneypotEvent(
                (base + timedelta(minutes=4, seconds=offset * 9)).isoformat(timespec="seconds"),
                stuffing,
                "ssh",
                22,
                "auth_failure",
                f"user-{offset + 1:03d}",
                "wordlist-a",
            )
        )

    # Pattern 3: one source producing many events over a longer period.
    repeater = "192.0.2.77"
    for offset in range(10):
        events.append(
            HoneypotEvent(
                (base + timedelta(minutes=offset * 4)).isoformat(timespec="seconds"),
                repeater,
                "http" if offset % 2 else "ssh",
                80 if offset % 2 else 22,
                "connect" if offset % 3 else "auth_failure",
                f"user-{offset % 3 + 1:03d}",
                "wordlist-b",
            )
        )

    # Background chatter uses documentation-range addresses only.
    noise_sources = ("198.51.100.10", "203.0.113.20", "192.0.2.90")
    for index in range(noise_events):
        events.append(
            HoneypotEvent(
                (base + timedelta(minutes=rng.randrange(0, 90), seconds=rng.randrange(0, 60))).isoformat(
                    timespec="seconds"
                ),
                noise_sources[index % len(noise_sources)],
                "http",
                8080,
                "connect",
            )
        )

    return tuple(
        sorted(events, key=lambda event: (event.timestamp, event.source_ip, event.service, event.port))
    )


def detect_scanning(events: Iterable[HoneypotEvent], limits: Thresholds) -> tuple[Finding, ...]:
    by_source: dict[str, list[HoneypotEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "connect":
            by_source[event.source_ip].append(event)

    findings: list[Finding] = []
    for source, items in by_source.items():
        ordered = sorted(items, key=lambda event: (_parse_timestamp(event.timestamp), event.port))
        left = 0
        for right in range(len(ordered)):
            while (
                _parse_timestamp(ordered[right].timestamp) - _parse_timestamp(ordered[left].timestamp)
            ).total_seconds() > limits.scan_window_seconds:
                left += 1
            ports = {item.port for item in ordered[left : right + 1]}
            if len(ports) >= limits.scan_ports:
                findings.append(
                    Finding(
                        "scanning",
                        "high",
                        source,
                        f"{len(ports)} distinct ports within {limits.scan_window_seconds}s",
                        len(ports),
                    )
                )
                break
    return tuple(findings)


def detect_credential_stuffing(events: Iterable[HoneypotEvent], limits: Thresholds) -> tuple[Finding, ...]:
    grouped: dict[str, list[HoneypotEvent]] = defaultdict(list)
    for event in events:
        if event.event_type in {"auth_failure", "auth_success"}:
            grouped[event.source_ip].append(event)

    findings: list[Finding] = []
    for source, items in grouped.items():
        failures = [item for item in items if item.event_type == "auth_failure"]
        usernames = {item.username for item in failures if item.username}
        successes = sum(1 for item in items if item.event_type == "auth_success")
        ratio = successes / len(items) if items else 1.0
        if len(usernames) >= limits.stuffing_usernames and ratio <= limits.max_success_ratio:
            labels = sorted({item.credential_label for item in failures if item.credential_label})
            findings.append(
                Finding(
                    "credential-stuffing",
                    "high",
                    source,
                    f"{len(usernames)} usernames tried, {successes} successes, labels={labels}",
                    len(usernames),
                )
            )
    return tuple(findings)


def detect_repeated_sources(events: Iterable[HoneypotEvent], limits: Thresholds) -> tuple[Finding, ...]:
    counts = Counter(event.source_ip for event in events)
    return tuple(
        Finding(
            "repeated-source",
            "medium",
            source,
            f"{count} events observed from one source",
            count,
        )
        for source, count in sorted(counts.items())
        if count >= limits.repeated_events
    )


def analyze(events: Iterable[HoneypotEvent], limits: Thresholds = Thresholds()) -> Analysis:
    events = tuple(events)
    findings = [
        *detect_scanning(events, limits),
        *detect_credential_stuffing(events, limits),
        *detect_repeated_sources(events, limits),
    ]
    findings.sort(key=lambda item: (SEVERITY_RANK.get(item.severity, 9), item.kind, item.source_ip))
    return Analysis(
        findings=tuple(findings),
        event_count=len(events),
        source_count=len({event.source_ip for event in events}),
    )


def render(analysis: Analysis) -> str:
    lines = [
        "=== HONEYPOT ANALYSIS (simulated) ===",
        f"Events: {analysis.event_count} | Sources: {analysis.source_count} | Findings: {len(analysis.findings)}",
    ]
    for finding in analysis.findings:
        lines.append(f"[{finding.severity}] {finding.kind} {finding.source_ip}")
        lines.append(f"    {finding.detail}")
    if not analysis.findings:
        lines.append("No findings above the configured thresholds.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic honeypot events (no listener, no real secrets).")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="analyze a JSON event capture")
    analyze_parser.add_argument("capture", type=Path)
    analyze_parser.add_argument("--scan-ports", type=int, default=5)
    analyze_parser.add_argument("--scan-window", type=int, default=300)
    analyze_parser.add_argument("--stuffing-usernames", type=int, default=5)
    analyze_parser.add_argument("--repeated-events", type=int, default=8)

    sample_parser = subparsers.add_parser("sample", help="analyze the built-in deterministic capture")
    sample_parser.add_argument("--json", action="store_true", help="print raw events instead of findings")

    args = parser.parse_args(argv)
    try:
        if args.command == "sample":
            events = generate_events()
            if args.json:
                print(
                    json.dumps(
                        [event.__dict__ for event in events],
                        indent=2,
                    )
                )
                return 0
            analysis = analyze(events)
        else:
            events = load_events(json.loads(args.capture.read_text(encoding="utf-8")))
            analysis = analyze(
                events,
                Thresholds(
                    scan_ports=args.scan_ports,
                    scan_window_seconds=args.scan_window,
                    stuffing_usernames=args.stuffing_usernames,
                    repeated_events=args.repeated_events,
                ),
            )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(analysis))
    return 0


if __name__ == "__main__":
    sys.exit(main())
