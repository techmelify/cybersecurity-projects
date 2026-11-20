#!/usr/bin/env python3
"""Offline, parse-only inspection of synthetic JWT-like token strings.

This is a defensive substitution: tokens are decoded and their claims are
reviewed, but they are never forged, signed, verified cryptographically, or
sent anywhere. A signature segment is treated as opaque text.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

__all__ = [
    "ParsedToken",
    "TokenFinding",
    "Inspection",
    "parse_token",
    "inspect_token",
    "format_inspection",
    "inspection_to_dict",
]

B64URL_RE = re.compile(r"[A-Za-z0-9_-]*\Z")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
DAY = 86400.0


@dataclass(frozen=True)
class ParsedToken:
    header: dict[str, object]
    claims: dict[str, object]
    signature: str
    segments: int


@dataclass(frozen=True)
class TokenFinding:
    code: str
    severity: str
    detail: str


@dataclass(frozen=True)
class Inspection:
    header: dict[str, object]
    claims: dict[str, object]
    findings: tuple[TokenFinding, ...]
    verdict: str


def _decode_segment(segment: str, label: str) -> dict[str, object]:
    if not B64URL_RE.fullmatch(segment):
        raise ValueError(f"{label} segment is not base64url")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} segment cannot be decoded") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} segment is not JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} segment must be a JSON object")
    return value


def parse_token(token: str) -> ParsedToken:
    """Split and decode the header/payload of a JWT-like string.

    No signature verification is performed; the third segment is kept as an
    opaque string so inspectors can note whether it is empty.
    """
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("token must have three dot-separated segments")
    return ParsedToken(
        header=_decode_segment(parts[0], "header"),
        claims=_decode_segment(parts[1], "payload"),
        signature=parts[2],
        segments=3,
    )


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _audiences(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple)):
        return {str(item) for item in value}
    return set()


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def inspect_token(
    token: str | ParsedToken,
    *,
    now: datetime | None = None,
    expected_aud: str | None = None,
    trusted_issuers: Iterable[str] = (),
    max_lifetime_days: float = 30.0,
) -> Inspection:
    """Check a synthetic token's algorithm and claims; return findings.

    When ``now`` is omitted, time-based checks are skipped and a
    ``time_reference_missing`` finding is included for transparency.
    """
    parsed = token if isinstance(token, ParsedToken) else parse_token(token)
    if max_lifetime_days <= 0:
        raise ValueError("max_lifetime_days must be positive")

    reference = _utc(now) if now is not None else None
    reference_ts = reference.timestamp() if reference is not None else None
    trusted = {str(name) for name in trusted_issuers}
    findings: list[TokenFinding] = []

    def add(code: str, severity: str, detail: str) -> None:
        findings.append(TokenFinding(code, severity, detail))

    alg = parsed.header.get("alg")
    alg_text = "" if alg is None else str(alg).lower()
    if not alg_text:
        add("alg_missing", "high", "header has no alg value")
    elif alg_text == "none":
        add("alg_none", "critical", "alg=none disables signature verification")

    if not parsed.signature:
        add("unsigned_token", "high", "third segment is empty; token is unsigned")

    if "exp" not in parsed.claims:
        add("exp_missing", "medium", "no expiry claim")
    else:
        exp = _number(parsed.claims["exp"])
        if exp is None:
            add("exp_invalid", "medium", "exp is not numeric")
        elif reference_ts is not None and reference_ts >= exp:
            add("expired", "high", f"exp={exp:.0f} is not in the future")
        elif reference_ts is not None and exp - reference_ts > 90 * DAY:
            add("long_lived_token", "low", "exp is more than 90 days away")

    iat = _number(parsed.claims.get("iat")) if "iat" in parsed.claims else None
    if "iat" not in parsed.claims:
        add("iat_missing", "low", "no issued-at claim")
    elif iat is None:
        add("iat_invalid", "medium", "iat is not numeric")
    elif reference_ts is not None and iat > reference_ts + 60:
        add("iat_in_future", "medium", "iat is more than one minute ahead of now")

    exp = _number(parsed.claims.get("exp"))
    if iat is not None and exp is not None:
        if iat >= exp:
            add("iat_after_exp", "medium", "iat is not earlier than exp")
        elif 0 < exp - iat > max_lifetime_days * DAY:
            add("long_lifetime", "low", f"lifetime exceeds {max_lifetime_days:g} days")

    if "aud" not in parsed.claims:
        add("aud_missing", "medium", "no audience claim")
    elif expected_aud is not None and expected_aud not in _audiences(parsed.claims["aud"]):
        add("aud_mismatch", "high", f"aud does not include {expected_aud!r}")

    if "iss" not in parsed.claims:
        add("iss_missing", "medium", "no issuer claim")
    else:
        issuer = str(parsed.claims["iss"])
        if trusted and issuer not in trusted:
            add("iss_untrusted", "high", f"issuer {issuer!r} is not on the trusted list")

    if reference_ts is None:
        add("time_reference_missing", "low", "no --now supplied; time checks skipped")

    highest = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    verdict = "reject" if highest >= 3 else "review" if highest == 2 else "allow"
    return Inspection(parsed.header, parsed.claims, tuple(findings), verdict)


def format_inspection(inspection: Inspection) -> str:
    lines = [
        f"Verdict: {inspection.verdict.upper()}",
        f"alg: {inspection.header.get('alg', '<missing>')}",
        f"exp: {inspection.claims.get('exp', '<missing>')}  "
        f"iat: {inspection.claims.get('iat', '<missing>')}",
        f"aud: {inspection.claims.get('aud', '<missing>')}  "
        f"iss: {inspection.claims.get('iss', '<missing>')}",
        "Findings:",
    ]
    if inspection.findings:
        lines.extend(
            f"  [{finding.severity.upper():8}] {finding.code}: {finding.detail}"
            for finding in inspection.findings
        )
    else:
        lines.append("  none")
    return "\n".join(lines)


def inspection_to_dict(inspection: Inspection) -> dict[str, object]:
    result: dict[str, object] = asdict(inspection)
    result["findings"] = [asdict(finding) for finding in inspection.findings]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect a synthetic JWT-like token (parse only).")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-t", "--token", help="token string to inspect")
    source.add_argument("-f", "--file", type=Path, help="file containing one token string")
    parser.add_argument("--now", help="ISO-8601 reference time for expiry checks")
    parser.add_argument("--expect-aud", help="expected audience value")
    parser.add_argument("--trusted-issuer", action="append", default=[], help="trusted issuer (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        token = args.token if args.token is not None else args.file.read_text(encoding="utf-8")
        reference = None
        if args.now:
            iso_text = args.now[:-1] + "+00:00" if args.now.endswith(("Z", "z")) else args.now
            reference = datetime.fromisoformat(iso_text)
        inspection = inspect_token(
            token,
            now=reference,
            expected_aud=args.expect_aud,
            trusted_issuers=args.trusted_issuer,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(inspection_to_dict(inspection), indent=2))
    else:
        print(format_inspection(inspection))
    return 0


if __name__ == "__main__":
    sys.exit(main())
