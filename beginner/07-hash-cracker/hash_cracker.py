#!/usr/bin/env python3
"""Educational hash cracker: dictionary and bounded brute-force attacks.

Lab use only. Hashes are computed locally from candidate strings; no rainbow
tables, no network, no real credential stores.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import string
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CrackResult", "digest", "dictionary_attack", "brute_force"]

_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


@dataclass(frozen=True)
class CrackResult:
    algorithm: str
    target: str
    plaintext: str | None
    attempts: int

    @property
    def found(self) -> bool:
        return self.plaintext is not None


def digest(plaintext: str, algorithm: str) -> str:
    try:
        factory = _ALGORITHMS[algorithm.lower()]
    except KeyError as exc:
        raise ValueError(f"unsupported algorithm: {algorithm}") from exc
    return factory(plaintext.encode("utf-8")).hexdigest()


def dictionary_attack(target: str, algorithm: str, words: list[str]) -> CrackResult:
    """Try each candidate in order, stopping at the first match."""
    wanted = target.strip().lower()
    for attempt, word in enumerate(words, start=1):
        candidate = word.rstrip("\r\n")
        if digest(candidate, algorithm) == wanted:
            return CrackResult(algorithm, wanted, candidate, attempt)
    return CrackResult(algorithm, wanted, None, len(words))


def brute_force(
    target: str,
    algorithm: str,
    charset: str = string.ascii_lowercase + string.digits,
    max_length: int = 4,
) -> CrackResult:
    """Enumerate every string up to max_length. Keep the bound small."""
    if max_length < 1:
        raise ValueError("max_length must be at least 1")
    wanted = target.strip().lower()
    attempts = 0
    for length in range(1, max_length + 1):
        for tuple_chars in itertools.product(charset, repeat=length):
            candidate = "".join(tuple_chars)
            attempts += 1
            if digest(candidate, algorithm) == wanted:
                return CrackResult(algorithm, wanted, candidate, attempts)
    return CrackResult(algorithm, wanted, None, attempts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Educational hash cracker (lab use only).")
    parser.add_argument("hash")
    parser.add_argument("-a", "--algorithm", default="sha256", choices=sorted(_ALGORITHMS))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-w", "--wordlist", type=Path)
    mode.add_argument("-b", "--brute", type=int, metavar="MAX_LENGTH")
    parser.add_argument("--charset", default=string.ascii_lowercase + string.digits)
    args = parser.parse_args(argv)

    if args.wordlist:
        words = args.wordlist.read_text(encoding="utf-8", errors="replace").splitlines()
        result = dictionary_attack(args.hash, args.algorithm, words)
    else:
        try:
            result = brute_force(args.hash, args.algorithm, args.charset, args.brute)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if result.found:
        print(f"FOUND {result.plaintext} ({result.algorithm}, {result.attempts} attempts)")
        return 0
    print(f"not found ({result.attempts} attempts)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
