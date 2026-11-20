#!/usr/bin/env python3
"""Audit HTTP response headers for missing or weak security controls.

Works offline against a headers file, or online with urllib when a URL is given.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.request import Request, urlopen

__all__ = ["Finding", "scan_headers", "score", "format_report", "fetch_headers"]


@dataclass(frozen=True)
class Finding:
    control: str
    status: str  # pass | warn | fail
    detail: str


def _get(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value.strip()
    return None


def _has_frame_ancestors(csp: str | None) -> bool:
    return bool(csp and "frame-ancestors" in csp.lower())


def scan_headers(headers: Mapping[str, str]) -> list[Finding]:
    """Evaluate a mapping of response headers and return one finding per control."""
    findings: list[Finding] = []

    csp = _get(headers, "Content-Security-Policy")
    if csp:
        findings.append(Finding("Content-Security-Policy", "pass", "present"))
    else:
        findings.append(Finding("Content-Security-Policy", "fail", "missing"))

    hsts = _get(headers, "Strict-Transport-Security")
    if hsts:
        max_age = 0
        for part in hsts.lower().split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        if max_age >= 31536000:
            findings.append(Finding("Strict-Transport-Security", "pass", f"max-age={max_age}"))
        else:
            findings.append(Finding("Strict-Transport-Security", "warn", "present but max-age is under one year"))
    else:
        findings.append(Finding("Strict-Transport-Security", "fail", "missing"))

    nosniff = _get(headers, "X-Content-Type-Options")
    if nosniff and nosniff.lower() == "nosniff":
        findings.append(Finding("X-Content-Type-Options", "pass", "nosniff"))
    else:
        findings.append(Finding("X-Content-Type-Options", "fail", "missing or not nosniff"))

    frame = _get(headers, "X-Frame-Options")
    if frame and frame.lower() in {"deny", "sameorigin"}:
        findings.append(Finding("X-Frame-Options", "pass", frame))
    elif _has_frame_ancestors(csp):
        findings.append(Finding("X-Frame-Options", "pass", "covered by CSP frame-ancestors"))
    elif frame:
        findings.append(Finding("X-Frame-Options", "warn", f"unexpected value: {frame}"))
    else:
        findings.append(Finding("X-Frame-Options", "fail", "missing"))

    referrer = _get(headers, "Referrer-Policy")
    if referrer and referrer.lower() in {"no-referrer", "strict-origin-when-cross-origin"}:
        findings.append(Finding("Referrer-Policy", "pass", referrer))
    elif referrer:
        findings.append(Finding("Referrer-Policy", "warn", f"weak policy: {referrer}"))
    else:
        findings.append(Finding("Referrer-Policy", "fail", "missing"))

    permissions = _get(headers, "Permissions-Policy")
    if permissions:
        findings.append(Finding("Permissions-Policy", "pass", "present"))
    else:
        findings.append(Finding("Permissions-Policy", "warn", "missing"))

    for header, label in (("Server", "Server banner"), ("X-Powered-By", "X-Powered-By")):
        value = _get(headers, header)
        if value:
            findings.append(Finding(label, "warn", f"exposes {value}"))
        else:
            findings.append(Finding(label, "pass", "not exposed"))

    return findings


def score(findings: list[Finding]) -> tuple[int, int]:
    """Return (points earned, points available); pass=1, warn=0.5, fail=0."""
    earned = sum({"pass": 1.0, "warn": 0.5, "fail": 0.0}[f.status] for f in findings)
    return int(earned), len(findings)


def format_report(target: str, findings: list[Finding]) -> str:
    earned, total = score(findings)
    lines = [f"Target: {target}", f"Score: {earned}/{total}", ""]
    lines.extend(f"  [{f.status.upper():4}] {f.control}: {f.detail}" for f in findings)
    return "\n".join(lines)


def parse_header_file(path: Path) -> dict[str, str]:
    """Parse `Name: value` lines from a local file."""
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        name, value = line.split(":", 1)
        result[name.strip()] = value.strip()
    return result


def fetch_headers(url: str, timeout: float = 5.0) -> dict[str, str]:
    """Fetch response headers from a URL. Use only on targets you own."""
    request = Request(url, method="GET", headers={"User-Agent": "header-audit/1.0"})
    with urlopen(request, timeout=timeout) as response:
        return dict(response.headers.items())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit HTTP security response headers.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("url", nargs="?", help="URL to fetch (only targets you own)")
    source.add_argument("-f", "--file", type=Path, help="local file of Name: value headers")
    args = parser.parse_args(argv)

    if args.file:
        headers, target = parse_header_file(args.file), str(args.file)
    else:
        try:
            headers, target = fetch_headers(args.url), args.url
        except Exception as exc:  # noqa: BLE001 - CLI should report and exit cleanly
            print(f"error: {exc}", file=sys.stderr)
            return 2

    print(format_report(target, scan_headers(headers)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
