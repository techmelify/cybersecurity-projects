#!/usr/bin/env python3
"""First-match firewall rule engine with CIDR and port ranges."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

__all__ = ["Packet", "Rule", "Decision", "evaluate", "load_rules"]


@dataclass(frozen=True)
class Packet:
    src: str
    dst: str
    port: int
    protocol: str = "tcp"


@dataclass(frozen=True)
class Rule:
    name: str
    action: str  # allow | deny
    src: str = "0.0.0.0/0"
    dst: str = "0.0.0.0/0"
    port: str = "1-65535"  # "80" or "80-443"
    protocol: str = "any"


@dataclass(frozen=True)
class Decision:
    action: str
    rule: str

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


def _in_cidr(address: str, cidr: str) -> bool:
    return ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False)


def _in_port(port: int, spec: str) -> bool:
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            low, high = part.split("-", 1)
            if int(low) <= port <= int(high):
                return True
        elif port == int(part):
            return True
    return False


def _matches(rule: Rule, packet: Packet) -> bool:
    return (
        _in_cidr(packet.src, rule.src)
        and _in_cidr(packet.dst, rule.dst)
        and _in_port(packet.port, rule.port)
        and rule.protocol in {"any", packet.protocol.lower()}
    )


def evaluate(packet: Packet, rules: Iterable[Rule]) -> Decision:
    for rule in rules:
        if _matches(rule, packet):
            return Decision(rule.action, rule.name)
    return Decision("deny", "default")


def load_rules(data: Iterable[Mapping[str, object]]) -> list[Rule]:
    return [
        Rule(
            str(item["name"]),
            str(item["action"]).lower(),
            str(item.get("src", "0.0.0.0/0")),
            str(item.get("dst", "0.0.0.0/0")),
            str(item.get("port", "1-65535")),
            str(item.get("protocol", "any")),
        )
        for item in data
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate packets against JSON firewall rules.")
    parser.add_argument("rules", type=Path)
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--protocol", default="tcp")
    args = parser.parse_args(argv)
    try:
        rules = load_rules(json.loads(args.rules.read_text(encoding="utf-8")))
        decision = evaluate(Packet(args.src, args.dst, args.port, args.protocol), rules)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{decision.action.upper()} ({decision.rule})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
