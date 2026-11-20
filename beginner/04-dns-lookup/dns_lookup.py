#!/usr/bin/env python3
"""DNS lookup CLI: forward, reverse, and basic WHOIS queries.

Network access only happens when the CLI is used; the core logic is injectable
so tests stay offline and deterministic.
"""

from __future__ import annotations

import argparse
import socket
import sys
from dataclasses import dataclass
from typing import Callable

__all__ = ["DnsResolver", "LookupResult", "make_default_resolver"]


@dataclass(frozen=True)
class LookupResult:
    query: str
    kind: str
    values: tuple[str, ...]

    def render(self) -> str:
        body = "\n".join(f"  {v}" for v in self.values) if self.values else "  (none)"
        return f"{self.kind} {self.query}\n{body}"


ResolverFn = Callable[[str], list[str]]


class DnsResolver:
    """Wrap lookup functions so they can be replaced in tests."""

    def __init__(self, a: ResolverFn, aaaa: ResolverFn, ptr: ResolverFn, whois: ResolverFn):
        self._a = a
        self._aaaa = aaaa
        self._ptr = ptr
        self._whois = whois

    def forward(self, host: str) -> LookupResult:
        values = sorted(set(self._a(host)))
        return LookupResult(host, "A", tuple(values))

    def ipv6(self, host: str) -> LookupResult:
        values = sorted(set(self._aaaa(host)))
        return LookupResult(host, "AAAA", tuple(values))

    def reverse(self, address: str) -> LookupResult:
        values = sorted(set(self._ptr(address)))
        return LookupResult(address, "PTR", tuple(values))

    def whois(self, domain: str) -> LookupResult:
        return LookupResult(domain, "WHOIS", tuple(self._whois(domain)))


def _system_a(host: str) -> list[str]:
    return list({
        info[4][0]
        for info in socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    })


def _system_aaaa(host: str) -> list[str]:
    return list({
        info[4][0]
        for info in socket.getaddrinfo(host, None, family=socket.AF_INET6, type=socket.SOCK_STREAM)
    })


def _system_ptr(address: str) -> list[str]:
    try:
        return [socket.gethostbyaddr(address)[0]]
    except socket.herror:
        return []


def _system_whois(domain: str) -> list[str]:
    """Minimal WHOIS over port 43 against IANA (no third-party API)."""
    with socket.create_connection(("whois.iana.org", 43), timeout=8) as sock:
        sock.sendall((domain + "\r\n").encode("ascii"))
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace").splitlines()


def make_default_resolver() -> DnsResolver:
    return DnsResolver(_system_a, _system_aaaa, _system_ptr, _system_whois)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DNS forward, reverse and WHOIS lookup.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("a", "IPv4 addresses"), ("aaaa", "IPv6 addresses"), ("whois", "IANA WHOIS")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("host")
    ptr = sub.add_parser("ptr", help="reverse DNS")
    ptr.add_argument("address")

    args = parser.parse_args(argv)
    resolver = make_default_resolver()
    try:
        if args.command == "a":
            result = resolver.forward(args.host)
        elif args.command == "aaaa":
            result = resolver.ipv6(args.host)
        elif args.command == "ptr":
            result = resolver.reverse(args.address)
        else:
            result = resolver.whois(args.host)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(result.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
