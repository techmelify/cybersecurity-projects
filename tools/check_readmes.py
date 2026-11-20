#!/usr/bin/env python3
"""QA check: every project README must carry the full visual identity."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TIERS = ("foundations", "beginner", "intermediate", "advanced")

REQUIREMENTS = {
    "hero image": "assets/hero.svg",
    "tier badge": "shields.io/badge/tier-",
    "mermaid diagram": "```mermaid",
    "real output": "real output",
    "test command": "python -m unittest discover",
    "learn link": "learn/README.md",
}


def main() -> int:
    problems: list[str] = []
    projects = 0
    for tier in TIERS:
        for folder in sorted(p for p in (ROOT / tier).iterdir() if p.is_dir()):
            projects += 1
            readme = folder / "README.md"
            key = f"{tier}/{folder.name}"
            if not readme.exists():
                problems.append(f"{key}: missing README.md")
                continue
            text = readme.read_text(encoding="utf-8").lower()
            for label, needle in REQUIREMENTS.items():
                if needle.lower() not in text:
                    problems.append(f"{key}: missing {label}")
            if not (folder / "learn" / "README.md").exists():
                problems.append(f"{key}: missing learn/README.md")
            if not (folder / "assets" / "hero.svg").exists():
                problems.append(f"{key}: missing assets/hero.svg")

    print(f"checked {projects} projects; {len(problems)} problem(s)")
    for item in problems:
        print("  " + item)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
