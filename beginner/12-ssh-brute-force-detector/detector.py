#!/usr/bin/env python3
"""Detect SSH brute-force patterns in auth logs.

Offline log analysis only. Accepts any iterable of log lines so tests are
deterministic and no live system is touched.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

__all__ = ["AuthEvent", "BruteForceAlert", "parse_auth_log", "detect_brute_force"]

_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_SUCCESS = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
_MONTHS = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}


@dataclass(frozen=True)
class AuthEvent:
    time: datetime
    kind: str  # fail | success
    user: str
    ip: str


@dataclass(frozen=True)
class BruteForceAlert:
    ip: str
    failures: int
    window_seconds: int
    unique_users: int
    followed_by_success: bool

    @property
    def message(self) -> str:
        return (
            f"{self.ip}: {self.failures} failures / {self.window_seconds}s, "
            f"{self.unique_users} user(s)"
            + (" then SUCCESS" if self.followed_by_success else "")
        )


def parse_auth_log(lines: Iterable[str], year: int = 2026) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or parts[0] not in _MONTHS:
            continue
        try:
            stamp = datetime.strptime(f"{year} {parts[0]} {parts[1]} {parts[2]}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        fail, success = _FAIL.search(line), _SUCCESS.search(line)
        if fail:
            events.append(AuthEvent(stamp, "fail", fail.group("user"), fail.group("ip")))
        elif success:
            events.append(AuthEvent(stamp, "success", success.group("user"), success.group("ip")))
    return events


def detect_brute_force(events: list[AuthEvent], threshold: int = 5, window: timedelta = timedelta(minutes=5)) -> list[BruteForceAlert]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    alerts: list[BruteForceAlert] = []
    for ip, ip_events in sorted(by_ip.items()):
        failures = sorted((e for e in ip_events if e.kind == "fail"), key=lambda e: e.time)
        if len(failures) < threshold:
            continue
        # Sliding window: find the largest cluster of failures inside `window`.
        best: list[AuthEvent] = []
        for start in failures:
            cluster = [f for f in failures if start.time <= f.time <= start.time + window]
            if len(cluster) > len(best):
                best = cluster
        if len(best) < threshold:
            continue
        success_after = any(
            e.kind == "success" and e.time >= best[-1].time and e.time <= best[-1].time + timedelta(minutes=10)
            for e in ip_events
        )
        alerts.append(
            BruteForceAlert(
                ip,
                len(best),
                int(window.total_seconds()),
                len({e.user for e in best}),
                success_after,
            )
        )
    return alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect SSH brute-force patterns in an auth log.")
    parser.add_argument("log", type=Path)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=300, help="seconds")
    args = parser.parse_args(argv)
    lines = args.log.read_text(encoding="utf-8", errors="replace").splitlines()
    events = parse_auth_log(lines)
    alerts = detect_brute_force(events, args.threshold, timedelta(seconds=args.window))
    for alert in alerts:
        print(alert.message)
    print(f"{len(alerts)} alert(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
