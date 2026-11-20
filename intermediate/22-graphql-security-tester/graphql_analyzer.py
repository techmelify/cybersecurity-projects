#!/usr/bin/env python3
"""Offline GraphQL query analyzer.

The analyzer measures depth, aliases, introspection fields, and batch size from
query text plus a declared server policy. It never connects to an endpoint.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "Token",
    "QueryMetrics",
    "Policy",
    "Snapshot",
    "Finding",
    "tokenize",
    "measure_query",
    "parse_snapshot",
    "analyze_snapshot",
    "main",
]

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<comment>\#[^\n]*)
    | (?P<block_string>\"\"\".*?\"\"\")
    | (?P<string>"(?:\\.|[^"\\])*")
    | (?P<spread>\.\.\.)
    | (?P<name>[_A-Za-z][_0-9A-Za-z]*)
    | (?P<number>-?\d+(?:\.\d+)?)
    | (?P<punct>[!(){}\[\]:=@$.,|&])
    """,
    re.DOTALL | re.VERBOSE,
)

_INTROSPECTION_FIELDS = frozenset({"__schema", "__type"})
_DEPTH_THRESHOLD = 8
_ALIAS_THRESHOLD = 10
_BATCH_THRESHOLD = 5
_PERMISSIVE_DEPTH = 20


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    pos: int


@dataclass(frozen=True)
class QueryMetrics:
    label: str
    max_depth: int
    alias_count: int
    introspection_fields: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    max_depth: int | None
    max_aliases: int | None
    max_batch_size: int | None


@dataclass(frozen=True)
class Snapshot:
    queries: tuple[QueryMetrics, ...]
    policy: Policy


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str  # low | medium | high
    detail: str
    recommendation: str


def tokenize(query: str) -> tuple[Token, ...]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(query):
        match = _TOKEN_RE.match(query, pos)
        if match is None:
            raise ValueError(f"unexpected character at offset {pos}: {query[pos]!r}")
        kind = match.lastgroup
        text = match.group()
        if kind not in ("ws", "comment"):
            tokens.append(Token(kind or "unknown", text, pos))
        pos = match.end()
    return tuple(tokens)


class _Parser:
    """Small structural parser; it records metrics without building a full AST."""

    def __init__(self, tokens: tuple[Token, ...]) -> None:
        self.tokens = tokens
        self.index = 0
        self.alias_count = 0
        self.introspection: set[str] = set()

    def peek(self, offset: int = 0) -> Token | None:
        position = self.index + offset
        if 0 <= position < len(self.tokens):
            return self.tokens[position]
        return None

    def advance(self) -> Token | None:
        token = self.peek()
        if token is not None:
            self.index += 1
        return token

    def accept(self, value: str) -> bool:
        token = self.peek()
        if token is not None and token.value == value:
            self.index += 1
            return True
        return False

    def expect(self, value: str) -> None:
        if not self.accept(value):
            token = self.peek()
            position = token.pos if token else "end"
            raise ValueError(f"expected {value!r} at {position}")

    def skip_balanced(self, opening: str, closing: str) -> None:
        if not self.accept(opening):
            return
        depth = 1
        while self.peek() is not None and depth:
            token = self.advance()
            if token.value == opening:
                depth += 1
            elif token.value == closing:
                depth -= 1

    def parse_directives(self) -> None:
        while self.accept("@"):
            token = self.peek()
            if token is not None and token.kind == "name":
                self.advance()
            if self.peek() is not None and self.peek().value == "(":
                self.skip_balanced("(", ")")

    def parse_document(self) -> int:
        max_depth = 0
        while self.peek() is not None:
            token = self.peek()
            if token.kind == "name" and token.value == "fragment":
                max_depth = max(max_depth, self.parse_fragment())
            elif token.kind == "name" and token.value in {"query", "mutation", "subscription"}:
                max_depth = max(max_depth, self.parse_operation())
            elif token.value == "{":
                max_depth = max(max_depth, self.parse_selection_set(1))
            else:
                self.advance()
        return max_depth

    def parse_operation(self) -> int:
        self.advance()
        token = self.peek()
        if token is not None and token.kind == "name":
            self.advance()
        if self.peek() is not None and self.peek().value == "(":
            self.skip_balanced("(", ")")
        self.parse_directives()
        if self.peek() is not None and self.peek().value == "{":
            return self.parse_selection_set(1)
        return 0

    def parse_fragment(self) -> int:
        self.advance()
        token = self.peek()
        if token is not None and token.kind == "name":
            self.advance()
        if self.accept("on"):
            token = self.peek()
            if token is not None and token.kind == "name":
                self.advance()
        self.parse_directives()
        if self.peek() is not None and self.peek().value == "{":
            return self.parse_selection_set(1)
        return 0

    def parse_selection_set(self, level: int) -> int:
        self.expect("{")
        max_depth = level
        while self.peek() is not None and self.peek().value != "}":
            token = self.peek()
            if token.value == ",":
                self.advance()
                continue
            if token.value == "...":
                self.advance()
                next_token = self.peek()
                if next_token is not None and next_token.kind == "name":
                    if next_token.value == "on":
                        self.advance()
                        type_token = self.peek()
                        if type_token is not None and type_token.kind == "name":
                            self.advance()
                    else:
                        self.advance()
                self.parse_directives()
                if self.peek() is not None and self.peek().value == "{":
                    max_depth = max(max_depth, self.parse_selection_set(level + 1))
                continue
            if token.kind != "name":
                self.advance()
                continue

            self.advance()
            field_name = token.value
            colon = self.peek()
            after_colon = self.peek(1)
            if colon is not None and colon.value == ":" and after_colon is not None and after_colon.kind == "name":
                self.advance()
                field_token = self.advance()
                field_name = field_token.value if field_token else field_name
                self.alias_count += 1

            if field_name in _INTROSPECTION_FIELDS:
                self.introspection.add(field_name)

            if self.peek() is not None and self.peek().value == "(":
                self.skip_balanced("(", ")")
            self.parse_directives()
            if self.peek() is not None and self.peek().value == "{":
                max_depth = max(max_depth, self.parse_selection_set(level + 1))
        self.expect("}")
        return max_depth


def measure_query(query: str, label: str = "query") -> QueryMetrics:
    parser = _Parser(tokenize(query))
    return QueryMetrics(
        label=label,
        max_depth=parser.parse_document(),
        alias_count=parser.alias_count,
        introspection_fields=tuple(sorted(parser.introspection)),
    )


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_snapshot(data: Mapping[str, Any]) -> Snapshot:
    queries: list[QueryMetrics] = []
    for index, item in enumerate(data.get("queries", []), start=1):
        if isinstance(item, str):
            label = f"query-{index}"
            text = item
        else:
            label = str(item.get("name", f"query-{index}"))
            text = str(item.get("query", ""))
        queries.append(measure_query(text, label))

    policy_data = data.get("server_policy", {})
    policy = Policy(
        max_depth=_optional_int(policy_data.get("max_depth")),
        max_aliases=_optional_int(policy_data.get("max_aliases")),
        max_batch_size=_optional_int(policy_data.get("max_batch_size")),
    )
    return Snapshot(tuple(queries), policy)


def analyze_snapshot(snapshot: Snapshot) -> list[Finding]:
    findings: list[Finding] = []

    deep = [(query.label, query.max_depth) for query in snapshot.queries if query.max_depth > _DEPTH_THRESHOLD]
    if deep:
        detail = ", ".join(f"{label}={depth}" for label, depth in deep)
        findings.append(
            Finding(
                "GQL-001",
                "Excessive query nesting",
                "high",
                f"depth exceeds {_DEPTH_THRESHOLD}: {detail}",
                "Enforce a server-side depth limit and reject oversized selections.",
            )
        )

    introspection = [(query.label, query.introspection_fields) for query in snapshot.queries if query.introspection_fields]
    if introspection:
        detail = ", ".join(f"{label}={'/'.join(fields)}" for label, fields in introspection)
        findings.append(
            Finding(
                "GQL-002",
                "Schema introspection requested",
                "medium",
                detail,
                "Disable introspection outside development or require authorization.",
            )
        )

    aliased = [(query.label, query.alias_count) for query in snapshot.queries if query.alias_count > _ALIAS_THRESHOLD]
    if aliased:
        detail = ", ".join(f"{label}={count}" for label, count in aliased)
        findings.append(
            Finding(
                "GQL-003",
                "Alias-heavy query",
                "medium",
                f"aliases exceed {_ALIAS_THRESHOLD}: {detail}",
                "Apply an alias-count limit and query-cost accounting.",
            )
        )

    batch_size = len(snapshot.queries)
    if batch_size > _BATCH_THRESHOLD:
        findings.append(
            Finding(
                "GQL-004",
                "Oversized request batch",
                "medium",
                f"batch_size={batch_size} exceeds {_BATCH_THRESHOLD}",
                "Limit the number of operations accepted in a single request.",
            )
        )

    depth_limit = snapshot.policy.max_depth
    if depth_limit is None or depth_limit <= 0:
        findings.append(
            Finding(
                "GQL-005",
                "No server-side depth limit configured",
                "high",
                "server_policy.max_depth is missing or not positive",
                "Configure and enforce an explicit maximum query depth.",
            )
        )
    elif depth_limit > _PERMISSIVE_DEPTH:
        findings.append(
            Finding(
                "GQL-005",
                "Server-side depth limit is too permissive",
                "medium",
                f"server_policy.max_depth={depth_limit} exceeds {_PERMISSIVE_DEPTH}",
                "Lower the configured maximum query depth.",
            )
        )

    unique = {(finding.id, finding.detail): finding for finding in findings}
    return [unique[key] for key in sorted(unique)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze GraphQL queries offline for depth, introspection, aliases, and batching risk."
    )
    parser.add_argument("snapshot", type=Path, help="JSON snapshot of queries and server policy")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = parser.parse_args(argv)

    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        findings = analyze_snapshot(parse_snapshot(data))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2, sort_keys=True))
    else:
        for finding in findings:
            print(
                f"[{finding.severity.upper():6}] {finding.id} {finding.title}: "
                f"{finding.detail} -> {finding.recommendation}"
            )
        print(f"findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
