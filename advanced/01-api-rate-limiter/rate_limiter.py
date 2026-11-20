#!/usr/bin/env python3
"""Token-bucket and sliding-window rate limiting over synthetic timestamps.

No Redis, server, sockets, or wall-clock time are used. Every request carries
an explicit timestamp, so all results are reproducible.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from typing import Sequence

__all__ = [
    "Request",
    "TokenBucketConfig",
    "SlidingWindowConfig",
    "Decision",
    "Outcome",
    "generate_requests",
    "evaluate_token_bucket",
    "evaluate_sliding_window",
    "outcome_to_dict",
    "main",
]


@dataclass(frozen=True)
class Request:
    """A synthetic API request identified by an explicit arrival time."""

    request_id: str
    timestamp: float

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("request_id must not be empty")
        if not math.isfinite(self.timestamp):
            raise ValueError("timestamp must be a finite number")


@dataclass(frozen=True)
class TokenBucketConfig:
    """Bucket capacity and token refill rate (tokens per second)."""

    capacity: float
    refill_rate: float

    def __post_init__(self) -> None:
        if self.capacity <= 0 or not math.isfinite(self.capacity):
            raise ValueError("capacity must be a positive finite number")
        if self.refill_rate < 0 or not math.isfinite(self.refill_rate):
            raise ValueError("refill_rate must be a non-negative finite number")


@dataclass(frozen=True)
class SlidingWindowConfig:
    """Maximum requests inside a trailing window of fixed length."""

    limit: int
    window_seconds: float

    def __post_init__(self) -> None:
        if self.limit < 1:
            raise ValueError("limit must be at least 1")
        if self.window_seconds <= 0 or not math.isfinite(self.window_seconds):
            raise ValueError("window_seconds must be a positive finite number")


@dataclass(frozen=True)
class Decision:
    """One algorithm's decision for one request."""

    algorithm: str
    request_id: str
    timestamp: float
    allowed: bool
    reason: str
    remaining: float

    def to_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "allowed": self.allowed,
            "reason": self.reason,
            "remaining": round(self.remaining, 6),
        }


@dataclass(frozen=True)
class Outcome:
    """All decisions from one limiter plus aggregate counters."""

    algorithm: str
    decisions: tuple[Decision, ...]
    allowed: int
    dropped: int


def generate_requests(
    count: int,
    start: float = 0.0,
    interval: float = 1.0,
    prefix: str = "req",
) -> tuple[Request, ...]:
    """Build a deterministic sequence of synthetic request timestamps."""
    if count < 0:
        raise ValueError("count must be non-negative")
    if not math.isfinite(start) or not math.isfinite(interval) or interval < 0:
        raise ValueError("start must be finite and interval must be finite and non-negative")
    return tuple(Request(f"{prefix}-{index:03d}", start + index * interval) for index in range(count))


def evaluate_token_bucket(requests: Sequence[Request], config: TokenBucketConfig) -> Outcome:
    """Simulate a token bucket that starts full at the first request time.

    Requests are processed in timestamp order using a stable sort, so equal
    timestamps keep their input order. Refill is continuous in wall time only
    in the mathematical sense: no clock is read.
    """
    ordered = sorted(requests, key=lambda request: request.timestamp)
    tokens = config.capacity
    previous = ordered[0].timestamp if ordered else 0.0
    decisions: list[Decision] = []
    allowed = 0

    for request in ordered:
        elapsed = max(0.0, request.timestamp - previous)
        tokens = min(config.capacity, tokens + elapsed * config.refill_rate)
        if tokens + 1e-9 >= 1.0:
            tokens = max(0.0, tokens - 1.0)
            allowed += 1
            decision = Decision("token-bucket", request.request_id, request.timestamp, True, "token available", tokens)
        else:
            decision = Decision("token-bucket", request.request_id, request.timestamp, False, "bucket empty", tokens)
        decisions.append(decision)
        previous = request.timestamp

    return Outcome("token-bucket", tuple(decisions), allowed, len(decisions) - allowed)


def evaluate_sliding_window(requests: Sequence[Request], config: SlidingWindowConfig) -> Outcome:
    """Simulate a trailing window; an event exactly ``window_seconds`` old expires."""
    ordered = sorted(requests, key=lambda request: request.timestamp)
    admitted: list[float] = []
    decisions: list[Decision] = []
    allowed = 0

    for request in ordered:
        while admitted and request.timestamp - admitted[0] >= config.window_seconds:
            admitted.pop(0)
        if len(admitted) < config.limit:
            admitted.append(request.timestamp)
            allowed += 1
            decision = Decision(
                "sliding-window", request.request_id, request.timestamp, True, "under limit", float(config.limit - len(admitted))
            )
        else:
            decision = Decision(
                "sliding-window", request.request_id, request.timestamp, False, "window full", float(config.limit - len(admitted))
            )
        decisions.append(decision)

    return Outcome("sliding-window", tuple(decisions), allowed, len(decisions) - allowed)


def outcome_to_dict(outcome: Outcome) -> dict[str, object]:
    return {
        "algorithm": outcome.algorithm,
        "allowed": outcome.allowed,
        "dropped": outcome.dropped,
        "decisions": [decision.to_dict() for decision in outcome.decisions],
    }


def _parse_timestamps(text: str) -> tuple[Request, ...]:
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if not parts:
        raise ValueError("no timestamps supplied")
    return tuple(Request(f"req-{index:03d}", float(part)) for index, part in enumerate(parts))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--timestamps", help="comma-separated synthetic arrival timestamps")
    source.add_argument("--generate", type=int, metavar="COUNT", help="generate COUNT evenly spaced requests")
    parser.add_argument("--start", type=float, default=0.0, help="first generated timestamp (default: 0)")
    parser.add_argument("--interval", type=float, default=1.0, help="spacing for generated requests (default: 1)")
    parser.add_argument("--capacity", type=float, default=2.0, help="token bucket capacity (default: 2)")
    parser.add_argument("--refill-rate", type=float, default=1.0, help="tokens added per second (default: 1)")
    parser.add_argument("--limit", type=int, default=3, help="sliding window request limit (default: 3)")
    parser.add_argument("--window-seconds", type=float, default=5.0, help="sliding window length (default: 5)")
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    args = parser.parse_args(argv)

    try:
        requests = _parse_timestamps(args.timestamps) if args.timestamps is not None else generate_requests(
            args.generate, args.start, args.interval
        )
        bucket = evaluate_token_bucket(requests, TokenBucketConfig(args.capacity, args.refill_rate))
        window = evaluate_sliding_window(requests, SlidingWindowConfig(args.limit, args.window_seconds))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"token_bucket": outcome_to_dict(bucket), "sliding_window": outcome_to_dict(window)}, indent=2))
        return 0

    for outcome in (bucket, window):
        print(f"[{outcome.algorithm}] allowed={outcome.allowed} dropped={outcome.dropped}")
        for decision in outcome.decisions:
            flag = "ALLOW" if decision.allowed else "DROP"
            print(f"  {decision.request_id:>8} t={decision.timestamp:<8g} {flag}  {decision.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
