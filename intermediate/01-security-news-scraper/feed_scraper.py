#!/usr/bin/env python3
"""Offline RSS/Atom fixture parser and keyword-based news ranker.

This is a Python substitution for the upstream Go scraper: it never opens a
socket. XML is supplied as a string or read from a local fixture file.
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterable, Mapping

__all__ = [
    "FeedItem",
    "RankedItem",
    "DEFAULT_KEYWORDS",
    "parse_feed",
    "rank_items",
    "format_report",
    "ranked_to_dict",
]

DEFAULT_KEYWORDS: dict[str, float] = {
    "cve": 3.0,
    "breach": 2.5,
    "vulnerability": 2.0,
    "ransomware": 2.0,
    "exploit": 1.5,
    "patch": 1.0,
    "advisory": 1.0,
}


@dataclass(frozen=True)
class FeedItem:
    title: str
    link: str
    published: datetime | None
    summary: str
    source: str


@dataclass(frozen=True)
class RankedItem:
    item: FeedItem
    score: float
    reasons: tuple[str, ...]


def _local_name(tag: str) -> str:
    """Strip XML namespaces and prefixes: '{urn:x}dc:date' -> 'date'."""
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1].lower()


def _text_of(element: ET.Element, *names: str) -> str:
    wanted = {name.lower() for name in names}
    for child in element:
        if _local_name(child.tag) in wanted:
            text = " ".join("".join(child.itertext()).split())
            if text:
                return text
    return ""


def _link_of(element: ET.Element) -> str:
    for child in element:
        if _local_name(child.tag) != "link":
            continue
        rel = (child.get("rel") or "alternate").lower()
        href = (child.get("href") or "").strip()
        if href and rel == "alternate":
            return href
        text = " ".join("".join(child.itertext()).split())
        if text and rel != "self":
            return text
    return ""


def _parse_date(value: str) -> datetime | None:
    """Accept ISO-8601 and RFC-822 dates; tolerate malformed fixture dates."""
    text = value.strip()
    if not text:
        return None
    iso_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _date_of(element: ET.Element) -> datetime | None:
    raw = _text_of(element, "published", "pubdate", "updated", "date", "modified")
    return _parse_date(raw) if raw else None


def _feed_title(root: ET.Element) -> str:
    for element in root.iter():
        if _local_name(element.tag) in {"channel", "feed"}:
            title = _text_of(element, "title")
            if title:
                return title
    return _text_of(root, "title") or "unknown"


def parse_feed(xml: str) -> list[FeedItem]:
    """Parse an RSS 2.0 or Atom XML document into a list of feed items.

    DTD declarations are rejected so fixtures cannot declare entities. The
    parser is deliberately offline: no URL is ever fetched.
    """
    if "<!doctype" in xml.lower():
        raise ValueError("DTD declarations are not allowed in feed fixtures")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError(f"invalid feed XML: {exc}") from exc

    source = _feed_title(root)
    items: list[FeedItem] = []
    for element in root.iter():
        if _local_name(element.tag) not in {"item", "entry"}:
            continue
        items.append(
            FeedItem(
                title=_text_of(element, "title") or "(untitled)",
                link=_link_of(element),
                published=_date_of(element),
                summary=_text_of(element, "summary", "description", "content"),
                source=source,
            )
        )
    return items


def _sort_time(value: datetime | None) -> float:
    return value.timestamp() if value is not None else float("-inf")


def rank_items(
    items: Iterable[FeedItem],
    keywords: Mapping[str, float] | None = None,
    *,
    now: datetime | None = None,
    half_life_days: float = 30.0,
) -> list[RankedItem]:
    """Rank items by keyword hits plus optional recency.

    Passing ``now`` makes recency scoring explicit and deterministic; when it
    is omitted no recency points are added, so results never depend on the
    machine clock.
    """
    if half_life_days <= 0:
        raise ValueError("half_life_days must be positive")

    reference = now
    if reference is not None and reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)

    weights = DEFAULT_KEYWORDS if keywords is None else keywords
    ranked: list[RankedItem] = []
    for item in items:
        haystack = f"{item.title} {item.summary}".lower()
        score = 0.0
        reasons: list[str] = []
        for word, weight in sorted(weights.items(), key=lambda pair: pair[0].lower()):
            needle = word.lower()
            if needle in haystack:
                score += float(weight)
                reasons.append(f"keyword:{word}({weight:g})")

        if reference is not None and item.published is not None:
            age_days = max(0.0, (reference - item.published).total_seconds() / 86400.0)
            recency = 3.0 * (0.5 ** (age_days / half_life_days))
            score += recency
            reasons.append(f"recency:{age_days:.1f}d")

        ranked.append(
            RankedItem(item=item, score=round(score, 3), reasons=tuple(reasons))
        )

    ranked.sort(
        key=lambda entry: (
            -entry.score,
            -_sort_time(entry.item.published),
            entry.item.title,
            entry.item.link,
        )
    )
    return ranked


def format_report(ranked: Iterable[RankedItem]) -> str:
    entries = list(ranked)
    if not entries:
        return "No feed items."
    lines: list[str] = []
    for index, entry in enumerate(entries, 1):
        when = entry.item.published.date().isoformat() if entry.item.published else "unknown date"
        lines.append(f"{index}. [{entry.score:5.2f}] {entry.item.title} ({when})")
        lines.append(f"     {entry.item.link or 'no link'} - {', '.join(entry.reasons) or 'no signals'}")
    return "\n".join(lines)


def ranked_to_dict(ranked: Iterable[RankedItem]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for entry in ranked:
        item = entry.item
        result.append(
            {
                "title": item.title,
                "link": item.link,
                "published": item.published.isoformat() if item.published else None,
                "summary": item.summary,
                "source": item.source,
                "score": entry.score,
                "reasons": list(entry.reasons),
            }
        )
    return result


def _parse_keywords(values: list[str] | None) -> dict[str, float] | None:
    if not values:
        return None
    result: dict[str, float] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"expected KEY=WEIGHT, got: {value}")
        key, weight = value.split("=", 1)
        result[key.strip().lower()] = float(weight.strip())
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse and rank a local RSS/Atom fixture.")
    parser.add_argument("-f", "--file", type=Path, required=True, help="local XML fixture (no network)")
    parser.add_argument("--keywords", nargs="+", metavar="KEY=WEIGHT", help="custom scoring weights")
    parser.add_argument("--now", help="ISO-8601 reference time for deterministic recency scoring")
    parser.add_argument("--limit", type=int, default=10, help="maximum items to show (default: 10)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        items = parse_feed(args.file.read_text(encoding="utf-8"))
        keywords = _parse_keywords(args.keywords)
        reference = _parse_date(args.now) if args.now else None
        if args.now and reference is None:
            raise ValueError(f"invalid --now value: {args.now}")
        if args.limit < 0:
            raise ValueError("--limit must not be negative")
        ranked = rank_items(items, keywords, now=reference)[: args.limit]
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(ranked_to_dict(ranked), indent=2))
    else:
        print(format_report(ranked))
    return 0


if __name__ == "__main__":
    sys.exit(main())
