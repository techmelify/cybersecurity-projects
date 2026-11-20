#!/usr/bin/env python3
"""Demonstrate unsafe deserialization and an allowlist-based defence.

Uses Python's pickle only with harmless in-repo gadgets. No system commands,
network access, or real exploit payloads are involved.
"""

from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path
from typing import Any

__all__ = ["UnsafeGadget", "LabGadget", "make_lab_payload", "unsafe_loads", "safe_loads"]


class UnsafeGadget(Exception):
    """Raised when a serialized stream tries to reference a blocked class."""


def _benign_marker(text: str) -> str:
    """A harmless function used only to prove code execution during unpickling."""
    return f"MARKER::{text}"


class LabGadget:
    """A harmless object whose reduce instruction calls `_benign_marker`."""

    def __init__(self, text: str = "lab"):
        self.text = text

    def __reduce__(self):
        return (_benign_marker, (self.text,))


def make_lab_payload(text: str = "lab") -> bytes:
    """Return a pickle that invokes only `_benign_marker` when loaded."""
    return pickle.dumps(LabGadget(text), protocol=4)


def unsafe_loads(data: bytes) -> Any:
    """Load with full pickle. For comparison only — never use on untrusted input."""
    return pickle.loads(data)


class _AllowlistUnpickler(pickle.Unpickler):
    def __init__(self, *args: Any, allowed_modules: frozenset[str], **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._allowed_modules = allowed_modules

    def find_class(self, module: str, name: str):
        if module not in self._allowed_modules:
            raise UnsafeGadget(f"blocked global: {module}.{name}")
        return super().find_class(module, name)


def safe_loads(data: bytes, allowed_modules: frozenset[str] = frozenset({"__main__"})) -> Any:
    """Load only globals from allowed modules. Plain data still works."""
    import io

    return _AllowlistUnpickler(io.BytesIO(data), allowed_modules=allowed_modules).load()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Demonstrate pickle gadget blocking.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("payload", help="write a harmless lab payload to stdout")
    check = sub.add_parser("check", help="load a payload with the allowlisted unpickler")
    check.add_argument("file", type=Path)
    check.add_argument("--allow-main", action="store_true", help="allow __main__ globals")
    args = parser.parse_args(argv)

    if args.command == "payload":
        sys.stdout.buffer.write(make_lab_payload())
        return 0

    data = args.file.read_bytes()
    allowed = frozenset({"__main__"}) if args.allow_main else frozenset()
    try:
        result = safe_loads(data, allowed)
    except (UnsafeGadget, pickle.UnpicklingError, EOFError) as exc:
        print(f"BLOCKED: {exc}")
        return 1
    print(f"ALLOWED: {result!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
