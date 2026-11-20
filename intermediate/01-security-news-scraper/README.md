# 01 — Security News Scraper

An offline RSS/Atom fixture parser that turns saved feeds into ranked security-news items.

> **Python substitution:** the upstream project is a Go network scraper. This version is a pure standard-library Python CLI that reads a local XML fixture by default and never opens a socket. There is deliberately no URL option, so behaviour is deterministic and safe in CI. Deviation from upstream: parsing and ranking are preserved; live fetching is replaced by fixture input.

## Run

```powershell
python feed_scraper.py --file fixture.xml
python feed_scraper.py --file fixture.xml --json --limit 5
python feed_scraper.py --file fixture.xml --now 2026-11-20T00:00:00Z --keywords cve=4 breach=2
```

`parse_feed(xml)` accepts RSS 2.0 and Atom (namespaced or plain) XML strings. `rank_items(items, keywords=None, now=None)` scores keyword hits in title/summary and, when an explicit `now` is supplied, adds a half-life recency bonus. Without `now`, no clock is read. Ties break on publication date, then title, then link.

DTD declarations are rejected, and malformed XML raises `ValueError`.

## Test

```powershell
python -m unittest discover -s tests -v
```

21 tests, standard library only, no network calls. All fixtures are synthetic XML embedded in the test file.

## Safety

Only local fixtures are read. Feed content is treated as untrusted text: it is never executed, and no external resources are resolved.
