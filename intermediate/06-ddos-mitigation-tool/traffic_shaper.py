#!/usr/bin/env python3
"""Token-bucket and sliding-window rate limiting over a synthetic request log.

This is a Python substitution for a live DDoS mitigation tool. It replays a
local JSONL log or a deterministic demo log; it opens no sockets, captures no
traffic, and changes no firewall or network state.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

__all__ = [
    "Request",
    "Decision",
    "SimulationResult",
    "token_bucket",
    "sliding_window",
    "simulate",
    "generate_requests",
    "load_requests",
    "format_report",
]

DEMO_CLIENTS = ("192.0.2.10", "192.0.2.11", "192.0.2.12")
DEMO_PATHS = ("/", "/login", "/api")


@dataclass(frozen=True)
class Request:
    time: float
    client: str
    path: str = "/"


@dataclass(frozen=True)
class Decision:
    request: Request
    allowed: bool
    algorithm: str
    reason: str


@dataclass(frozen=True)
class SimulationResult:
    token_bucket: tuple[Decision, ...]
    sliding_window: tuple[Decision, ...]
    combined: tuple[Decision, ...]
    allowed: int
    dropped: int


def _ordered(requests: Iterable[Request]) -> list[Request]:
    ordered: list[Request] = []
    for request in requests:
        if not isinstance(request, Request):
            raise TypeError("requests must contain Request instances")
        if not math.isfinite(request.time) or request.time < 0:
            raise ValueError("request time must be a finite non-negative number")
        if not request.client:
            raise ValueError("request client must not be empty")
        ordered.append(request)
    return sorted(ordered, key=lambda item: (item.time, item.client, item.path))


def token_bucket(
    requests: Iterable[Request],
    *,
    capacity: float,
    refill_per_second: float,
    initial_tokens: float | None = None,
) -> list[Decision]:
    """Allow a request when its client's bucket contains a whole token."""
    if capacity <= 0:
        raise ValueError("capacity must be positive")
    if refill_per_second < 0:
        raise ValueError("refill_per_second must not be negative")
    starting = capacity if initial_tokens is None else initial_tokens
    if not 0 <= starting <= capacity:
        raise ValueError("initial_tokens must be between 0 and capacity")

    states: dict[str, list[float]] = {}
    decisions: list[Decision] = []
    for request in _ordered(requests):
        state = states.setdefault(request.client, [starting, request.time])
        elapsed = max(0.0, request.time - state[1])
        tokens = min(capacity, state[0] + elapsed * refill_per_second)
        if tokens >= 1.0:
            tokens -= 1.0
            decisions.append(Decision(request, True, "token_bucket", "token_available"))
        else:
            decisions.append(Decision(request, False, "token_bucket", "bucket_empty"))
        state[0] = tokens
        state[1] = request.time
    return decisions


def sliding_window(
    requests: Iterable[Request],
    *,
    limit: int,
    window_seconds: float,
) -> list[Decision]:
    """Allow at most ``limit`` requests per client in a rolling time window."""
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    states: dict[str, deque[float]] = {}
    decisions: list[Decision] = []
    for request in _ordered(requests):
        timestamps = states.setdefault(request.client, deque())
        cutoff = request.time - window_seconds
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) < limit:
            timestamps.append(request.time)
            decisions.append(Decision(request, True, "sliding_window", "under_limit"))
        else:
            decisions.append(Decision(request, False, "sliding_window", "window_full"))
    return decisions


def simulate(
    requests: Iterable[Request],
    *,
    capacity: float = 5.0,
    refill_per_second: float = 1.0,
    initial_tokens: float | None = None,
    window_limit: int = 10,
    window_seconds: float = 60.0,
) -> SimulationResult:
    """Run both algorithms and report where they agree or block."""
    records = _ordered(requests)
    bucket = token_bucket(
        records,
        capacity=capacity,
        refill_per_second=refill_per_second,
        initial_tokens=initial_tokens,
    )
    window = sliding_window(records, limit=window_limit, window_seconds=window_seconds)

    combined: list[Decision] = []
    for bucket_decision, window_decision in zip(bucket, window):
        if bucket_decision.allowed and window_decision.allowed:
            combined.append(Decision(bucket_decision.request, True, "combined", "both_allowed"))
        elif not bucket_decision.allowed:
            combined.append(
                Decision(bucket_decision.request, False, "combined", "blocked_by_token_bucket")
            )
        else:
            combined.append(
                Decision(bucket_decision.request, False, "combined", "blocked_by_sliding_window")
            )

    allowed = sum(1 for decision in combined if decision.allowed)
    return SimulationResult(
        tuple(bucket), tuple(window), tuple(combined), allowed, len(combined) - allowed
    )


def generate_requests(
    count: int = 20,
    *,
    seed: int = 7,
    clients: Iterable[str] = DEMO_CLIENTS,
    paths: Iterable[str] = DEMO_PATHS,
) -> list[Request]:
    """Create a deterministic synthetic request log (no network involved)."""
    if count < 0:
        raise ValueError("count must not be negative")
    rng = random.Random(seed)
    client_list = list(clients)
    path_list = list(paths)
    if not client_list or not path_list:
        raise ValueError("clients and paths must not be empty")

    result: list[Request] = []
    moment = 0.0
    for _ in range(count):
        moment += rng.uniform(0.05, 0.6)
        result.append(
            Request(round(moment, 3), rng.choice(client_list), rng.choice(path_list))
        )
    return result


def load_requests(path: Path) -> list[Request]:
    """Read a JSONL log of synthetic requests from a local file."""
    requests: list[Request] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {number}: invalid JSON") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"line {number}: request must be an object")
        try:
            requests.append(
                Request(
                    time=float(raw["time"]),
                    client=str(raw["client"]),
                    path=str(raw.get("path", "/")),
                )
            )
        except KeyError as exc:
            raise ValueError(f"line {number}: missing field {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise ValueError(f"line {number}: invalid request fields") from exc
    return requests


def format_report(result: SimulationResult) -> str:
    total = len(result.combined)
    bucket_allowed = sum(1 for decision in result.token_bucket if decision.allowed)
    window_allowed = sum(1 for decision in result.sliding_window if decision.allowed)
    lines = [
        "Traffic shaping simulation (synthetic log)",
        f"Requests: {total}",
        f"Allowed: {result.allowed}",
        f"Dropped: {result.dropped}",
        f"token_bucket allowed: {bucket_allowed}",
        f"sliding_window allowed: {window_allowed}",
        "Decisions:",
    ]
    if not result.combined:
        lines.append("  none")
    for decision in result.combined:
        state = "ALLOW" if decision.allowed else "DROP "
        lines.append(
            f"  t={decision.request.time:.3f} client={decision.request.client} "
            f"path={decision.request.path} {state} {decision.reason}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulate rate limits over a synthetic request log.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--log", type=Path, help="local JSONL request log")
    source.add_argument("--demo", action="store_true", help="use a deterministic synthetic log")
    parser.add_argument("--count", type=int, default=20, help="demo request count (default: 20)")
    parser.add_argument("--seed", type=int, default=7, help="demo random seed")
    parser.add_argument("--capacity", type=float, default=5.0, help="token bucket capacity")
    parser.add_argument("--rate", type=float, default=1.0, help="tokens refilled per second")
    parser.add_argument("--initial-tokens", type=float, default=None, help="starting tokens")
    parser.add_argument("--window-limit", type=int, default=10, help="sliding window request limit")
    parser.add_argument("--window", type=float, default=60.0, help="sliding window length in seconds")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        requests = generate_requests(args.count, seed=args.seed) if args.demo else load_requests(args.log)
        result = simulate(
            requests,
            capacity=args.capacity,
            refill_per_second=args.rate,
            initial_tokens=args.initial_tokens,
            window_limit=args.window_limit,
            window_seconds=args.window,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print(format_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
