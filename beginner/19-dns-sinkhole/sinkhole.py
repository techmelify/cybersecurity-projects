#!/usr/bin/env python3
"""Dry-run-capable hosts-file blocklist manager.

Upstream specifies Go; this build is Python. It manages a marked block in a
hosts file. No DNS server is started and nothing is written unless --apply is
given.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["BEGIN", "END", "merge_hosts", "parse_blocklist"]

BEGIN = "# BEGIN cybersecurity-projects sinkhole"
END = "# END cybersecurity-projects sinkhole"


@dataclass(frozen=True)
class MergeResult:
    lines: tuple[str, ...]
    added: int
    removed: int


def parse_blocklist(text: str) -> list[str]:
    domains: list[str] = []
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        domain = entry.split()[-1].lower().rstrip(".")
        if domain and " " not in domain:
            domains.append(domain)
    return sorted(set(domains))


def merge_hosts(existing: str, domains: list[str], sinkhole_ip: str = "0.0.0.0") -> MergeResult:
    lines = existing.splitlines()
    try:
        start = lines.index(BEGIN)
        end = lines.index(END)
        if end < start:
            raise ValueError
        kept = lines[:start] + lines[end + 1 :]
        removed = end - start - 1
    except ValueError:
        kept, removed = lines, 0

    block = [BEGIN]
    block.extend(f"{sinkhole_ip} {domain}" for domain in sorted(set(domains)))
    block.append(END)
    while kept and kept[-1].strip() == "":
        kept.pop()
    return MergeResult(tuple(kept + block), len(domains), removed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage a hosts-file sinkhole block.")
    parser.add_argument("hosts", type=Path)
    parser.add_argument("blocklist", type=Path)
    parser.add_argument("--ip", default="0.0.0.0")
    parser.add_argument("--apply", action="store_true", help="write the hosts file (default: dry run)")
    args = parser.parse_args(argv)
    try:
        domains = parse_blocklist(args.blocklist.read_text(encoding="utf-8"))
        existing = args.hosts.read_text(encoding="utf-8") if args.hosts.exists() else ""
        result = merge_hosts(existing, domains, args.ip)
        if args.apply:
            args.hosts.write_text("\n".join(result.lines) + "\n", encoding="utf-8")
            print(f"applied: {result.added} domains, {result.removed} old lines removed")
        else:
            print("\n".join(result.lines))
            print(f"# DRY RUN: {result.added} domains, {result.removed} old lines would be removed", file=sys.stderr)
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
