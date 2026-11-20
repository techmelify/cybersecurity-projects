#!/usr/bin/env python3
"""Evaluate nginx-like access rules against one synthetic request.

Python substitution of the Lua/Nginx edge backend. Rules and requests come
from JSON or CLI arguments supplied by the caller; no web server, socket, or
network access is involved. Rules are first-match-wins, as with nginx access.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

__all__ = ["Rule", "Request", "Decision", "evaluate", "load_rules", "load_request"]


@dataclass(frozen=True)
class Rule:
    """One access-control rule.

    ``path`` may be ``"*"`` (all paths), a trailing-wildcard prefix such as
    ``"/api/*"``, or an exact path. ``header`` is an optional name/value pair.
    """

    name: str
    action: str  # "allow" or "deny"
    path: str = "*"
    method: str = "any"
    cidr: str = "0.0.0.0/0"
    header: tuple[str, str] | None = None


@dataclass(frozen=True)
class Request:
    """A synthetic HTTP request to evaluate."""

    path: str
    method: str
    ip: str
    headers: Mapping[str, str]


@dataclass(frozen=True)
class Decision:
    """The action taken and the rule that decided it."""

    action: str
    rule: str

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


def _path_matches(rule: Rule, request: Request) -> bool:
    if rule.path == "*":
        return True
    if rule.path.endswith("*"):
        return request.path.startswith(rule.path[:-1])
    return request.path == rule.path


def _header_matches(rule: Rule, request: Request) -> bool:
    if rule.header is None:
        return True
    name, expected = rule.header
    actual = next(
        (value for key, value in request.headers.items() if key.lower() == name.lower()),
        None,
    )
    return actual == expected


def _matches(rule: Rule, request: Request) -> bool:
    return (
        _path_matches(rule, request)
        and rule.method.lower() in {"any", request.method.lower()}
        and ipaddress.ip_address(request.ip)
        in ipaddress.ip_network(rule.cidr, strict=False)
        and _header_matches(rule, request)
    )


def evaluate(
    request: Request,
    rules: Iterable[Rule],
    default: str = "deny",
) -> Decision:
    """Return the decision from the first matching rule, or ``default``."""
    for rule in rules:
        if _matches(rule, request):
            return Decision(rule.action, rule.name)
    return Decision(default, "default")


def load_rules(data: Iterable[Mapping[str, object]]) -> list[Rule]:
    """Parse a JSON list of rule mappings into :class:`Rule` objects."""
    rules: list[Rule] = []
    for item in data:
        header = item.get("header")
        header_pair: tuple[str, str] | None = None
        if header is not None:
            if not isinstance(header, (list, tuple)) or len(header) != 2:
                raise TypeError("header must be a two-element list")
            header_pair = (str(header[0]), str(header[1]))
        rules.append(
            Rule(
                name=str(item["name"]),
                action=str(item["action"]).lower(),
                path=str(item.get("path", "*")),
                method=str(item.get("method", "any")),
                cidr=str(item.get("cidr", "0.0.0.0/0")),
                header=header_pair,
            )
        )
    return rules


def load_request(data: Mapping[str, object]) -> Request:
    """Parse a JSON request mapping into a :class:`Request` object."""
    headers = data.get("headers", {})
    if not isinstance(headers, Mapping):
        raise TypeError("headers must be an object")
    return Request(
        path=str(data["path"]),
        method=str(data.get("method", "GET")),
        ip=str(data["ip"]),
        headers={str(key): str(value) for key, value in headers.items()},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a synthetic request against nginx-like JSON access rules."
    )
    parser.add_argument("rules", type=Path, help="JSON list of access rules")
    parser.add_argument("--path", required=True, help="request path, e.g. /api/admin")
    parser.add_argument("--method", default="GET", help="request method (default: GET)")
    parser.add_argument("--ip", required=True, help="client IP address")
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="request header; repeat as needed",
    )
    args = parser.parse_args(argv)

    headers: dict[str, str] = {}
    for raw in args.header:
        if "=" not in raw:
            print("error: header must be NAME=VALUE", file=sys.stderr)
            return 2
        name, value = raw.split("=", 1)
        headers[name] = value

    try:
        rules = load_rules(json.loads(args.rules.read_text(encoding="utf-8")))
        request = Request(args.path, args.method, args.ip, headers)
        decision = evaluate(request, rules)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"{decision.action.upper()} ({decision.rule})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
