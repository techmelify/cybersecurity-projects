#!/usr/bin/env python3
"""Static detector for trojan-like patterns in application artifacts.

The upstream synopsis asked for a *builder*; this project deliberately implements
only the defensive detector. No payloads, packers, or installers are produced.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

__all__ = ["Finding", "scan_artifact"]

_EXEC_PATTERNS = ("subprocess.", "os.system", "shell=True", "CreateProcess", "ShellExecute")
_DECODE_PATTERNS = ("b64decode", "frombase64string", "eval(", "exec(")
_PERSIST_PATTERNS = ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "crontab", "systemctl enable", "launchctl load")
_PACKER_PATTERNS = ("upx", "themida", "vmprotect")


@dataclass(frozen=True)
class Finding:
    artifact: str
    file: str
    severity: str
    reason: str


def scan_artifact(name: str, files: Mapping[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    all_text = "\n".join(files.values()).lower()

    has_exec = any(p.lower() in all_text for p in _EXEC_PATTERNS)
    has_decode = any(p.lower() in all_text for p in _DECODE_PATTERNS)
    has_persist = any(p.lower() in all_text for p in _PERSIST_PATTERNS)

    for path, text in sorted(files.items()):
        lowered = text.lower()
        for pattern in _EXEC_PATTERNS:
            if pattern.lower() in lowered:
                findings.append(Finding(name, path, "medium", f"execution primitive: {pattern}"))
        for pattern in _DECODE_PATTERNS:
            if pattern.lower() in lowered:
                findings.append(Finding(name, path, "medium", f"dynamic decode/eval: {pattern}"))
        for pattern in _PERSIST_PATTERNS:
            if pattern.lower() in lowered:
                findings.append(Finding(name, path, "high", f"persistence marker: {pattern}"))
        for pattern in _PACKER_PATTERNS:
            if pattern in lowered:
                findings.append(Finding(name, path, "low", f"packer reference: {pattern}"))

    if has_exec and has_decode and has_persist:
        findings.append(Finding(name, "<artifact>", "high", "execution + decoding + persistence indicators combined"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a JSON artifact snapshot for trojan-like indicators.")
    parser.add_argument("snapshot", type=Path, help='JSON: {"artifact": {"file": "text"}}')
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        findings = [f for name, files in data.items() for f in scan_artifact(name, files)]
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"[{finding.severity.upper():6}] {finding.artifact}/{finding.file}: {finding.reason}")
    print(f"{len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
