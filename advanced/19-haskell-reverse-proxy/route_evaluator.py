#!/usr/bin/env python3
"""Config-driven reverse-proxy ROUTE EVALUATOR.

This module only evaluates routing rules. It never opens sockets, accepts
connections, or forwards traffic.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "Request",
    "Route",
    "Decision",
    "load_routes",
    "route_matches",
    "evaluate",
    "main",
]


@dataclass(frozen=True)
class Request:
    host: str
    path: str = "/"
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)

    def normalized_headers(self) -> dict[str, str]:
        return {str(name).lower(): str(value) for name, value in self.headers.items()}


@dataclass(frozen=True)
class Route:
    name: str
    action: str  # "upstream" or "deny"
    host: str = "*"
    path: str = "/"
    methods: tuple[str, ...] = ()
    headers: Mapping[str, str] = field(default_factory=dict)
    upstream: str = ""


@dataclass(frozen=True)
class Decision:
    action: str
    route: str
    upstream: str = ""

    @property
    def allowed(self) -> bool:
        return self.action == "upstream"


def _host_matches(pattern: str, host: str) -> bool:
    expected = pattern.strip().lower()
    if expected in {"", "*"}:
        return True
    actual = host.strip().lower()
    if actual == expected:
        return True
    if actual.startswith("[") and "]" in actual:
        actual = actual[1 : actual.index("]")]
    elif ":" in expected or ":" not in actual:
        return False
    else:
        actual = actual.rsplit(":", 1)[0]
    return actual == expected


def _path_matches(prefix: str, path: str) -> bool:
    stripped = prefix.strip().strip("/")
    pattern = f"/{stripped}" if stripped else "/"
    target = path or "/"
    if pattern == "/":
        return True
    return target == pattern or target.startswith(f"{pattern}/")


def _method_matches(methods: tuple[str, ...], method: str) -> bool:
    if not methods:
        return True
    allowed = {item.strip().upper() for item in methods}
    return method.strip().upper() in allowed


def _headers_match(required: Mapping[str, str], request: Request) -> bool:
    available = request.normalized_headers()
    for name, expected in required.items():
        key = str(name).lower()
        if key not in available:
            return False
        wanted = str(expected)
        if wanted != "*" and available[key] != wanted:
            return False
    return True


def route_matches(route: Route, request: Request) -> bool:
    """Return True when every configured route condition matches a request."""

    return (
        _host_matches(route.host, request.host)
        and _path_matches(route.path, request.path)
        and _method_matches(route.methods, request.method)
        and _headers_match(route.headers, request)
    )


def evaluate(request: Request, routes: Iterable[Route]) -> Decision:
    """First matching route decides; no match is a default deny."""

    for route in routes:
        if route_matches(route, request):
            if route.action == "deny":
                return Decision("deny", route.name)
            return Decision("upstream", route.name, route.upstream)
    return Decision("deny", "default")


def load_routes(data: Mapping[str, object] | Iterable[Mapping[str, object]]) -> list[Route]:
    """Parse a JSON route list or an object of the form {"routes": [...]}."""

    items = data.get("routes", []) if isinstance(data, Mapping) else data
    routes: list[Route] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ValueError("each route must be a JSON object")
        action = str(item.get("action", "deny")).lower()
        if action not in {"upstream", "deny"}:
            raise ValueError(f"unsupported route action: {action}")
        methods = item.get("methods", ())
        if isinstance(methods, str):
            methods = (methods,)
        raw_headers = item.get("headers", {})
        if not isinstance(raw_headers, Mapping):
            raise ValueError("route headers must be a JSON object")
        routes.append(
            Route(
                name=str(item.get("name", "unnamed")),
                action=action,
                host=str(item.get("host", "*")),
                path=str(item.get("path", "/")),
                methods=tuple(str(method) for method in methods),
                headers={str(key): str(value) for key, value in raw_headers.items()},
                upstream=str(item.get("upstream", "")),
            )
        )
    return routes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a request against JSON proxy routes (rules only, no proxying)."
    )
    parser.add_argument("routes", type=Path, help="JSON route list or {'routes': [...]}")
    parser.add_argument("--host", required=True)
    parser.add_argument("--path", default="/")
    parser.add_argument("--method", default="GET")
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="request header; repeat for multiple headers",
    )
    args = parser.parse_args(argv)

    try:
        headers: dict[str, str] = {}
        for entry in args.header:
            if "=" not in entry:
                raise ValueError(f"invalid header (expected NAME=VALUE): {entry}")
            name, value = entry.split("=", 1)
            headers[name.strip()] = value.strip()
        routes = load_routes(json.loads(args.routes.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    decision = evaluate(Request(args.host, args.path, args.method, headers), routes)
    if decision.allowed:
        print(f"UPSTREAM {decision.upstream or '-'} ({decision.route})")
    else:
        print(f"DENY ({decision.route})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
