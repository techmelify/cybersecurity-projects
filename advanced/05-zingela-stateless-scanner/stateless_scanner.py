#!/usr/bin/env python3
"""Offline parser and risk matcher for saved nmap-like scan text.

Zig is replaced by Python. This tool never opens a socket, never invokes nmap,
and never touches a live target: it only reads a saved report and matches it
against a local risk catalog.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

__all__ = [
    "PortFinding",
    "HostFinding",
    "RiskEntry",
    "RiskMatch",
    "parse_scan",
    "match_risks",
    "load_catalog",
    "demo_scan",
    "DEFAULT_CATALOG",
    "SEVERITY_RANK",
    "main",
]

_HOST_RE = re.compile(r"^Nmap scan report for (?P<name>\S+)(?:\s+\((?P<address>[^)]+)\))?\s*$")
_PORT_RE = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>[A-Za-z]+)\s+"
    r"(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$"
)
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class PortFinding:
    """One parsed port row from a saved scan."""

    port: int
    protocol: str
    state: str
    service: str
    version: str = ""

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if not self.protocol or not self.state or not self.service:
            raise ValueError("protocol, state, and service must not be empty")


@dataclass(frozen=True)
class HostFinding:
    """One host block from a saved scan."""

    address: str
    hostname: str = ""
    ports: tuple[PortFinding, ...] = ()


@dataclass(frozen=True)
class RiskEntry:
    """A local catalog rule; an empty port set means any port for that service."""

    service: str
    severity: str
    note: str
    ports: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        if not self.service:
            raise ValueError("service must not be empty")
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity: {self.severity!r}")


@dataclass(frozen=True)
class RiskMatch:
    """A host/port/service that matched a catalog rule."""

    address: str
    port: int
    service: str
    severity: str
    note: str


DEFAULT_CATALOG: tuple[RiskEntry, ...] = (
    RiskEntry("telnet", "critical", "cleartext legacy remote login", frozenset({23})),
    RiskEntry("ftp", "high", "cleartext file transfer service"),
    RiskEntry("rlogin", "high", "legacy trust-based remote login"),
    RiskEntry("netbios-ssn", "high", "legacy file-sharing service"),
    RiskEntry("microsoft-ds", "high", "SMB file-sharing service"),
    RiskEntry("redis", "high", "in-memory store often exposed without authentication", frozenset({6379})),
    RiskEntry("mongodb", "high", "database often exposed without authentication", frozenset({27017})),
    RiskEntry("mysql", "medium", "database service should not be broadly reachable"),
    RiskEntry("postgresql", "medium", "database service should not be broadly reachable"),
    RiskEntry("http", "medium", "unencrypted web service"),
    RiskEntry("ssh", "low", "remote administration service"),
    RiskEntry("https", "info", "encrypted web service"),
)


def parse_scan(text: str) -> tuple[HostFinding, ...]:
    """Parse nmap-like text into immutable host and port findings."""
    hosts: list[HostFinding] = []
    current_address: str | None = None
    current_hostname = ""
    current_ports: list[PortFinding] = []

    def flush() -> None:
        nonlocal current_address, current_hostname, current_ports
        if current_address is not None:
            hosts.append(HostFinding(current_address, current_hostname, tuple(current_ports)))
        current_address, current_hostname, current_ports = None, "", []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        host_match = _HOST_RE.match(line)
        if host_match:
            flush()
            name = host_match.group("name")
            current_address = host_match.group("address") or name
            current_hostname = "" if current_address == name else name
            continue

        port_match = _PORT_RE.match(line)
        if port_match and current_address is not None:
            port = int(port_match.group("port"))
            current_ports.append(
                PortFinding(
                    port,
                    port_match.group("proto").lower(),
                    port_match.group("state").lower(),
                    port_match.group("service").lower(),
                    (port_match.group("version") or "").strip(),
                )
            )

    flush()
    return tuple(hosts)


def match_risks(
    hosts: Sequence[HostFinding],
    catalog: Sequence[RiskEntry] = DEFAULT_CATALOG,
    min_severity: str = "info",
) -> tuple[RiskMatch, ...]:
    """Match open ports against the catalog; only open ports are considered."""
    if min_severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {min_severity!r}")
    threshold = SEVERITY_RANK[min_severity]
    matches: list[RiskMatch] = []

    for host in hosts:
        for finding in host.ports:
            if finding.state != "open":
                continue
            for entry in catalog:
                if finding.service != entry.service.lower():
                    continue
                if entry.ports and finding.port not in entry.ports:
                    continue
                if SEVERITY_RANK[entry.severity] < threshold:
                    continue
                matches.append(RiskMatch(host.address, finding.port, finding.service, entry.severity, entry.note))
    return tuple(matches)


def load_catalog(path: Path) -> tuple[RiskEntry, ...]:
    """Load a JSON list of catalog entries from disk."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise ValueError("catalog must be a JSON list")
    entries = []
    for item in document:
        raw_ports = item.get("ports", [])
        if not isinstance(raw_ports, list):
            raise ValueError("catalog 'ports' must be a list")
        entries.append(
            RiskEntry(
                str(item["service"]),
                str(item["severity"]),
                str(item.get("note", "")),
                frozenset(int(port) for port in raw_ports),
            )
        )
    return tuple(entries)


def demo_scan() -> str:
    """Return a deterministic synthetic saved-scan document."""
    return """\
Nmap scan report for 192.0.2.10
Host is up (0.004s latency).
PORT     STATE  SERVICE     VERSION
22/tcp   open   ssh         OpenSSH 9.0
23/tcp   open   telnet      Linux telnetd
80/tcp   open   http        nginx 1.24
443/tcp  closed https

Nmap scan report for lab-host (192.0.2.20)
Host is up.
PORT     STATE  SERVICE     VERSION
6379/tcp open   redis       Redis 7.0
8080/tcp filtered http-proxy
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("scan_file", type=Path, nargs="?", help="saved nmap-like text file")
    source.add_argument("--demo", action="store_true", help="use a built-in synthetic scan")
    parser.add_argument("--catalog", type=Path, help="optional JSON catalog override")
    parser.add_argument("--min-severity", default="info", help="info|low|medium|high|critical (default: info)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.demo == (args.scan_file is not None):
        print("error: supply either a scan file or --demo", file=sys.stderr)
        return 1

    try:
        text = demo_scan() if args.demo else Path(args.scan_file).read_text(encoding="utf-8")
        catalog = load_catalog(args.catalog) if args.catalog else DEFAULT_CATALOG
        hosts = parse_scan(text)
        risks = match_risks(hosts, catalog, args.min_severity)
    except (ValueError, OSError, json.JSONDecodeError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "hosts": [
                        {
                            "address": host.address,
                            "hostname": host.hostname,
                            "ports": [
                                {
                                    "port": p.port,
                                    "protocol": p.protocol,
                                    "state": p.state,
                                    "service": p.service,
                                    "version": p.version,
                                }
                                for p in host.ports
                            ],
                        }
                        for host in hosts
                    ],
                    "risks": [
                        {
                            "address": r.address,
                            "port": r.port,
                            "service": r.service,
                            "severity": r.severity,
                            "note": r.note,
                        }
                        for r in risks
                    ],
                },
                indent=2,
            )
        )
        return 0

    for host in hosts:
        label = f"{host.hostname} ({host.address})" if host.hostname else host.address
        print(f"host {label}: {len(host.ports)} port(s)")
    for risk in risks:
        print(f"  [{risk.severity.upper()}] {risk.address}:{risk.port}/{risk.service} - {risk.note}")
    print(f"summary: {len(hosts)} host(s), {len(risks)} risk(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
