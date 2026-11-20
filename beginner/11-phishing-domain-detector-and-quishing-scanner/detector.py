#!/usr/bin/env python3
"""Defensive detector for lookalike domains and QR-payload red flags.

This project detects suspicious indicators only. It deliberately does not
generate phishing domains or quishing QR codes.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

__all__ = ["DomainFinding", "QRFinding", "scan_domain", "scan_qr_payload"]

_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ё": "e",
        "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "І": "I", "Ё": "E",
    }
)
_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "rebrand.ly"}


@dataclass(frozen=True)
class DomainFinding:
    domain: str
    normalized: str
    score: int
    reasons: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return self.score >= 3


@dataclass(frozen=True)
class QRFinding:
    payload: str
    score: int
    reasons: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return self.score >= 2


def _host(domain: str) -> str:
    text = domain.strip().lower()
    if "://" in text:
        text = urlparse(text).hostname or text
    return text.split("/")[0].rstrip(".")


def _normalize(host: str) -> str:
    # Decode punycode first, then fold lookalike Unicode characters to ASCII.
    try:
        decoded = host.encode("ascii").decode("idna") if host.isascii() else host
    except UnicodeError:
        decoded = host
    decoded = decoded.translate(_HOMOGLYPHS)
    try:
        ascii_form = decoded.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_form = decoded
    return ascii_form.lower().replace("-", "")


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def scan_domain(domain: str, brands: tuple[str, ...] = ("example", "examplebank")) -> DomainFinding:
    host = _host(domain)
    normalized = _normalize(host)
    score = 0
    reasons: list[str] = []

    if host != normalized:
        score += 3
        reasons.append("homoglyph, punycode, or hyphen normalization changed the name")
    if host.count("-") >= 2:
        score += 1
        reasons.append("multiple hyphens")

    label = normalized.split(".")[0]
    for brand in brands:
        brand_norm = brand.lower().replace("-", "")
        if brand_norm == label:
            continue
        distance = _levenshtein(label, brand_norm)
        if 0 < distance <= 2 and len(label) >= 4:
            score += 3
            reasons.append(f"near-match to brand '{brand}' (edit distance {distance})")
            break
        if brand_norm in label and label != brand_norm:
            score += 2
            reasons.append(f"brand '{brand}' embedded in a longer label")
            break
    return DomainFinding(host, normalized, score, tuple(reasons))


def scan_qr_payload(payload: str) -> QRFinding:
    score = 0
    reasons: list[str] = []
    text = payload.strip()
    parsed = urlparse(text if "://" in text else "http://" + text)
    host = (parsed.hostname or "").lower()

    if host in _SHORTENERS:
        score += 2
        reasons.append("URL shortener hides the final destination")
    if "xn--" in host:
        score += 2
        reasons.append("punycode host")
    try:
        import ipaddress

        ipaddress.ip_address(host)
        score += 1
        reasons.append("raw IP address instead of a domain")
    except ValueError:
        pass
    if parsed.scheme == "http":
        score += 1
        reasons.append("plain HTTP")
    if "login" in parsed.path.lower() or "verify" in parsed.path.lower():
        score += 1
        reasons.append("credential-themed path")

    return QRFinding(text, score, tuple(reasons))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect suspicious domains and QR payloads.")
    sub = parser.add_subparsers(dest="command", required=True)
    dom = sub.add_parser("domain", help="score one domain")
    dom.add_argument("domain")
    dom.add_argument("--brand", action="append", default=[])
    qr = sub.add_parser("qr", help="score a QR payload string")
    qr.add_argument("payload")
    args = parser.parse_args(argv)

    if args.command == "domain":
        brands = tuple(args.brand) or ("example", "examplebank")
        result = asdict(scan_domain(args.domain, brands))
    else:
        result = asdict(scan_qr_payload(args.payload))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
