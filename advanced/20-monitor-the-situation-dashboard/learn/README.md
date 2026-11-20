# Learn — aggregating a situation dashboard

## Normalizing severity

Feeds from different tools label severity differently (`HIGH`, `high`, `critical`). Lowercasing and mapping to a canonical order makes counts comparable. Unknown labels should not disappear; keep them in a deterministic trailing group.

## Ranking sources

A top-N view needs a tie-break rule. Sorting by `(-count, name)` produces the same order for the same input, which matters for reproducible reports and tests.

## Timeline buckets

Bucketing floors each timestamp to a fixed interval, such as 15 minutes. Filling gaps between the first and last bucket shows quiet periods instead of implying continuous activity. Since the range comes from the events themselves, reports do not depend on the wall clock.

## Synthetic feeds

A seeded pseudo-random generator creates repeatable sample data. That makes it possible to demonstrate the dashboard, test rendering, and discuss alert triage without connecting to real telemetry.
