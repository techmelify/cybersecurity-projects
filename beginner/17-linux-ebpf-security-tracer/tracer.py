#!/usr/bin/env python3
"""Offline tracer-event analyzer inspired by an eBPF security tracer.

Upstream specifies Python/C with live eBPF. This build consumes synthetic JSON
events only — no kernel access, no tracing privileges, no runtime hooks.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

__all__ = ["Alert", "analyze"]


@dataclass(frozen=True)
class Alert:
    event_index: int
    severity: str
    reason: str
    evidence: str


def _writable_path(path: str) -> bool:
    lowered = path.lower()
    return any(p in lowered for p in ("/tmp/", "/var/tmp/", "/dev/shm/"))


def analyze(events: Iterable[Mapping[str, object]]) -> list[Alert]:
    alerts: list[Alert] = []
    for index, event in enumerate(events):
        etype = str(event.get("type", "")).lower()
        path = str(event.get("path", ""))
        comm = str(event.get("comm", "")).lower()
        parent = str(event.get("parent_comm", "")).lower()
        uid = event.get("uid", 1000)

        if etype == "exec":
            if _writable_path(path):
                alerts.append(Alert(index, "high", "execution from writable path", path))
            if parent in {"nginx", "apache2", "httpd", "php-fpm"} and comm in {"sh", "bash", "python", "python3"}:
                alerts.append(Alert(index, "high", "web server spawned a shell/interpreter", f"{parent} -> {comm}"))
            if uid == 0 and comm in {"sh", "bash", "curl", "wget"}:
                alerts.append(Alert(index, "medium", "root spawned network/shell utility", comm))
        elif etype == "network":
            dst = str(event.get("dst", ""))
            try:
                addr = ipaddress.ip_address(dst)
                if not addr.is_private and not addr.is_loopback:
                    alerts.append(Alert(index, "low", "outbound connection to public IP", dst))
            except ValueError:
                pass
    return alerts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze synthetic tracer events from JSON Lines.")
    parser.add_argument("events", type=Path)
    args = parser.parse_args(argv)
    try:
        parsed = [json.loads(line) for line in args.events.read_text(encoding="utf-8").splitlines() if line.strip()]
        alerts = analyze(parsed)
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for alert in alerts:
        print(f"[{alert.severity.upper():6}] event#{alert.event_index}: {alert.reason} — {alert.evidence}")
    print(f"{len(alerts)} alert(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
