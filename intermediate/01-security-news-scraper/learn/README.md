# Learn — feed parsing and deterministic ranking

## RSS versus Atom

- **RSS 2.0** nests `<item>` elements inside `<channel>`. Dates use RFC-822, e.g. `Wed, 18 Nov 2026 12:00:00 +0000`.
- **Atom** uses `<entry>` elements, usually in the `http://www.w3.org/2005/Atom` namespace. Dates are ISO-8601, and links are attributes: `<link href="..." rel="alternate"/>`.

The parser compares *local* tag names (the part after `}` or `:`), so both formats and prefixed variants work with one code path. `email.utils.parsedate_to_datetime` handles RFC-822; `datetime.fromisoformat` handles ISO-8601. Naive timestamps are interpreted as UTC so comparisons never depend on the host timezone.

## Why fixtures instead of HTTP

A scraper that fetches live pages makes tests flaky, slow, and dependent on third parties. Feeding a fixed XML string to the same parser gives repeatable results and keeps the project offline. This is the substance of the **Python substitution** described in the main README.

## Ranking design

Each keyword contributes a fixed weight when it appears (case-insensitively) in the title or summary. Recency is an exponential decay: `3.0 * 0.5 ** (age_days / half_life_days)`. Supplying `now` explicitly means the score is a pure function of the input, which is essential for tests.

Sorting on `(-score, -timestamp, title, link)` makes equal scores deterministic. Items without a date sort after dated ones because their timestamp sorts as negative infinity.

## Parsing untrusted XML

`xml.etree.ElementTree` does not resolve external entities, but DTD declarations can still enable entity-expansion abuses. The parser rejects any document containing `<!DOCTYPE` before parsing, which removes that class of input entirely.
