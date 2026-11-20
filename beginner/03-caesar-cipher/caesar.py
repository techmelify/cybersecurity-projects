#!/usr/bin/env python3
"""Caesar cipher CLI with brute-force and automatic shift scoring."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

__all__ = ["shift_text", "brute_force", "score_english", "Candidate"]


@dataclass(frozen=True)
class Candidate:
    shift: int
    text: str
    score: float


# Approximate English letter frequencies (percent).
_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2,
    "g": 2.0, "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0,
    "m": 2.4, "n": 6.7, "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0,
    "s": 6.3, "t": 9.1, "u": 2.8, "v": 0.98, "w": 2.4, "x": 0.15,
    "y": 2.0, "z": 0.074,
}


def shift_text(text: str, shift: int, *, decode: bool = False) -> str:
    """Shift alphabetic characters; all other characters pass through."""
    amount = -shift if decode else shift
    result: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr((ord(char) - 97 + amount) % 26 + 97))
        elif "A" <= char <= "Z":
            result.append(chr((ord(char) - 65 + amount) % 26 + 65))
        else:
            result.append(char)
    return "".join(result)


def score_english(text: str) -> float:
    """Score text by closeness to English letter frequencies (higher is better)."""
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0
    total = len(letters)
    return sum(_FREQ.get(c, 0.0) for c in letters) / total


def brute_force(ciphertext: str) -> list[Candidate]:
    """Return all 26 shifts, sorted best first by English-likeness."""
    candidates = [
        Candidate(shift, shift_text(ciphertext, shift, decode=True), score_english(shift_text(ciphertext, shift, decode=True)))
        for shift in range(26)
    ]
    return sorted(candidates, key=lambda c: (-c.score, c.shift))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Caesar cipher encode/decode/brute-force.")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode")
    enc.add_argument("text")
    enc.add_argument("-s", "--shift", type=int, required=True)

    dec = sub.add_parser("decode")
    dec.add_argument("text")
    dec.add_argument("-s", "--shift", type=int, required=True)

    crack = sub.add_parser("crack")
    crack.add_argument("text")
    crack.add_argument("-n", "--top", type=int, default=5)

    args = parser.parse_args(argv)
    if args.command in {"encode", "decode"}:
        print(shift_text(args.text, args.shift, decode=args.command == "decode"))
        return 0

    for candidate in brute_force(args.text)[: max(1, args.top)]:
        print(f"[{candidate.shift:2}] {candidate.score:5.2f}  {candidate.text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
