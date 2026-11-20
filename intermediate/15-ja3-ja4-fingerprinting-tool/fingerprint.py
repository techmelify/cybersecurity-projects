#!/usr/bin/env python3
"""Compute JA3-style TLS fingerprints from synthetic ClientHello field lists.

Python substitution of the Rust-based upstream tool. Inputs are lists of
integers supplied by the caller; no packet capture, socket, or TLS handshake
is performed. MD5 here is used only as the JA3 hash primitive, not for security.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "ClientHello",
    "Fingerprint",
    "ja3_string",
    "ja3_hash",
    "ja4_like_hash",
    "fingerprint",
    "load_hellos",
]


@dataclass(frozen=True)
class ClientHello:
    """Synthetic ClientHello fields, kept as immutable integer tuples."""

    version: int
    ciphers: tuple[int, ...] = ()
    extensions: tuple[int, ...] = ()
    curves: tuple[int, ...] = ()
    formats: tuple[int, ...] = ()


@dataclass(frozen=True)
class Fingerprint:
    """The canonical JA3 string plus JA3 and simplified JA4-like digests."""

    ja3_string: str
    ja3: str
    ja4_like: str


def _join(values: Iterable[int]) -> str:
    return "-".join(str(int(value)) for value in values)


def ja3_string(hello: ClientHello) -> str:
    """Build the canonical ``version,ciphers,extensions,curves,formats`` string."""
    return ",".join(
        (
            str(hello.version),
            _join(hello.ciphers),
            _join(hello.extensions),
            _join(hello.curves),
            _join(hello.formats),
        )
    )


def ja3_hash(hello: ClientHello) -> str:
    """Return the 32-character MD5 hex digest used by JA3."""
    return hashlib.md5(ja3_string(hello).encode("ascii")).hexdigest()


def ja4_like_hash(hello: ClientHello) -> str:
    """Return a simplified, order-insensitive JA4-like digest.

    This is intentionally *not* wire-compatible with real JA4: for learning
    purposes it sorts and de-duplicates each list, prefixes the cipher count,
    and takes the first 16 hex characters of SHA-256.
    """
    ciphers = sorted(set(hello.ciphers))
    extensions = sorted(set(hello.extensions))
    curves = sorted(set(hello.curves))
    formats = sorted(set(hello.formats))
    canonical = "|".join(
        (
            str(hello.version),
            str(len(ciphers)),
            _join(ciphers),
            _join(extensions),
            _join(curves),
            _join(formats),
        )
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()[:16]


def fingerprint(hello: ClientHello) -> Fingerprint:
    """Compute both digests for one synthetic ClientHello."""
    return Fingerprint(
        ja3_string=ja3_string(hello),
        ja3=ja3_hash(hello),
        ja4_like=ja4_like_hash(hello),
    )


def load_hellos(data: Iterable[Mapping[str, object]]) -> list[ClientHello]:
    """Parse JSON records into ``ClientHello`` objects with integer tuples."""
    hellos: list[ClientHello] = []
    for item in data:
        hellos.append(
            ClientHello(
                version=int(item["version"]),
                ciphers=tuple(int(value) for value in item.get("ciphers", [])),
                extensions=tuple(int(value) for value in item.get("extensions", [])),
                curves=tuple(int(value) for value in item.get("curves", [])),
                formats=tuple(int(value) for value in item.get("formats", [])),
            )
        )
    return hellos


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fingerprint synthetic ClientHello field lists from JSON."
    )
    parser.add_argument("snapshot", type=Path, help="JSON list of ClientHello records")
    parser.add_argument(
        "--algo",
        choices=("all", "ja3", "ja4"),
        default="all",
        help="which digest to print (default: all)",
    )
    args = parser.parse_args(argv)

    try:
        hellos = load_hellos(json.loads(args.snapshot.read_text(encoding="utf-8")))
        results = [fingerprint(hello) for hello in hellos]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for index, result in enumerate(results):
        if args.algo == "ja3":
            print(f"{index} ja3={result.ja3}")
        elif args.algo == "ja4":
            print(f"{index} ja4_like={result.ja4_like}")
        else:
            print(f"{index} ja3={result.ja3} ja4_like={result.ja4_like}")
    print(f"{len(results)} fingerprint(s) computed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
