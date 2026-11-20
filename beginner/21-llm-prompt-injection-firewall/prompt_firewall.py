#!/usr/bin/env python3
"""Heuristic prompt-injection firewall.

Scores untrusted text for common manipulation patterns before it reaches an
LLM. Deterministic, offline, and transparent — no model calls.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = ["Verdict", "scan_prompt"]

_PATTERNS: tuple[tuple[str, int, str], ...] = (
    (r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts|rules)", 5, "instruction override"),
    (r"disregard (all |any |the )?(previous|prior|above)", 5, "instruction override"),
    (r"(reveal|show|print|repeat) (the |your )?(system|developer) (prompt|message|instructions)", 5, "system prompt extraction"),
    (r"you are now (a |an )?(dan|unrestricted|developer mode)", 4, "jailbreak persona"),
    (r"do not (tell|inform|alert) (the )?user", 4, "concealment request"),
    (r"^\s*system\s*:", 3, "role spoofing"),
    (r"<\s*\|?im_start\|?>\s*system", 4, "chat template injection"),
    (r"translate the above.*into.*base64", 3, "encoding obfuscation request"),
)


@dataclass(frozen=True)
class Verdict:
    score: int
    action: str  # allow | review | block
    reasons: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


def _base64_ratio(text: str) -> float:
    tokens = re.findall(r"[A-Za-z0-9+/=_-]{32,}", text)
    if not tokens:
        return 0.0
    decoded = 0
    for token in tokens:
        try:
            normalized = token.replace("-", "+").replace("_", "/")
            if base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True):
                decoded += len(token)
        except (binascii.Error, ValueError):
            continue
    return decoded / max(len(text), 1)


def scan_prompt(text: str, block_threshold: int = 6, review_threshold: int = 3) -> Verdict:
    lowered = text.lower()
    score = 0
    reasons: list[str] = []
    for pattern, weight, label in _PATTERNS:
        if re.search(pattern, lowered, flags=re.MULTILINE):
            score += weight
            reasons.append(label)

    if _base64_ratio(text) > 0.4:
        score += 2
        reasons.append("large base64-like blob")

    if score >= block_threshold:
        action = "block"
    elif score >= review_threshold:
        action = "review"
    else:
        action = "allow"
    return Verdict(score, action, tuple(reasons))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score untrusted prompt text for injection patterns.")
    parser.add_argument("text", nargs="?")
    parser.add_argument("--file", type=Path)
    args = parser.parse_args(argv)
    if args.text is None and args.file is None:
        parser.error("provide text or --file")
    text = args.file.read_text(encoding="utf-8") if args.file else args.text
    assert text is not None
    print(json.dumps(asdict(scan_prompt(text)), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
