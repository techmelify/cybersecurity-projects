#!/usr/bin/env python3
"""Educational key-event recorder.

NOT stealthy: no global hook, no persistence, no exfiltration, no background
install. Events come from an explicit source you provide. The demo source reads
lines from stdin. Use only on your own machine with informed consent.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

__all__ = ["KeyEvent", "KeyLogger", "stdin_source"]


@dataclass(frozen=True)
class KeyEvent:
    key: str
    timestamp: float


class KeyLogger:
    """Record key events in memory and optionally write them as JSON Lines."""

    def __init__(self) -> None:
        self._events: list[KeyEvent] = []
        self._running = False

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def record(self, key: str, timestamp: float | None = None) -> None:
        if not self._running:
            raise RuntimeError("logger is not running")
        if not key:
            raise ValueError("key must not be empty")
        self._events.append(KeyEvent(key, timestamp if timestamp is not None else time.time()))

    @property
    def events(self) -> tuple[KeyEvent, ...]:
        return tuple(self._events)

    def save(self, path: Path) -> int:
        path = Path(path)
        with path.open("w", encoding="utf-8") as handle:
            for event in self._events:
                handle.write(json.dumps(asdict(event)) + "\n")
        return len(self._events)

    def clear(self) -> None:
        self._events.clear()


def stdin_source() -> Iterator[str]:
    """Yield one character per typed input line. Explicit, visible, no hook."""
    for line in sys.stdin:
        for char in line.rstrip("\r\n"):
            yield char


def run(source: Iterable[str], output: Path) -> int:
    logger = KeyLogger()
    logger.start()
    try:
        for key in source:
            logger.record(key)
    finally:
        logger.stop()
    return logger.save(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Educational key-event recorder (stdin demo).")
    parser.add_argument("-o", "--output", type=Path, default=Path("keys.jsonl"))
    parser.add_argument("--i-understand", action="store_true", help="confirm local, consented use")
    args = parser.parse_args(argv)

    if not args.i_understand:
        print("refusing to start: pass --i-understand after reading the safety notes in README.md", file=sys.stderr)
        return 2

    print("Recording stdin only. Press Ctrl+C to stop.", file=sys.stderr)
    count = run(stdin_source(), args.output)
    print(f"wrote {count} events to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
