#!/usr/bin/env python3
"""Async TCP port scanner.

Lab use only: scan hosts you own or have written permission to test.
"""

from __future__ import annotations

import argparse
import asyncio
import socket
import sys
from dataclasses import dataclass

__all__ = ["PortResult", "parse_ports", "scan_port", "scan"]


@dataclass(frozen=True)
class PortResult:
    port: int
    open: bool
    service: str


def parse_ports(spec: str) -> list[int]:
    """Parse `80`, `1-100`, or `22,80,443` into a sorted unique list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            lo, hi = int(start), int(end)
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"invalid range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError(f"invalid port: {part}")
            ports.add(port)
    return sorted(ports)


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


async def scan_port(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """Try a single TCP connection; a successful connect means the port is open."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return PortResult(port, True, _service_name(port))
    except (OSError, asyncio.TimeoutError, ConnectionError):
        return PortResult(port, False, "-")


async def scan(host: str, ports: list[int], timeout: float = 1.0, concurrency: int = 100) -> list[PortResult]:
    """Scan ports with a bounded number of concurrent connections."""
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def bounded(port: int) -> PortResult:
        async with semaphore:
            return await scan_port(host, port, timeout)

    results = await asyncio.gather(*(bounded(p) for p in ports))
    return list(results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Async TCP port scanner (lab use only).")
    parser.add_argument("host", help="target hostname or IP")
    parser.add_argument("-p", "--ports", default="1-1024", help="ports: 80, 1-100, or 22,80,443")
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    parser.add_argument("-c", "--concurrency", type=int, default=100)
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results = asyncio.run(scan(args.host, ports, args.timeout, args.concurrency))
    for result in results:
        if result.open:
            print(f"{result.port}/tcp open  {result.service}")
    print(f"scanned {len(results)} ports; {sum(r.open for r in results)} open")
    return 0


if __name__ == "__main__":
    sys.exit(main())
