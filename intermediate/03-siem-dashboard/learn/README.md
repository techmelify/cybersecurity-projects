# Learn — event correlation without a web stack

## What a SIEM actually does

At its simplest, a SIEM ingests events, normalises them, aggregates by useful dimensions, and applies rules. This project models those four steps with plain functions:

1. `parse_event` normalises one JSON object into an `Event` with consistent field names and lower-cased type/severity.
2. `parse_events` reads a JSONL stream, skipping blank lines and attaching line numbers to errors.
3. `correlate` builds `Counter`-based aggregates and evaluates five small rules.
4. `format_dashboard` / `--json` present the result.

## Why the CLI substitution

A Flask/React dashboard adds HTTP, JavaScript, and browser state to every test. Replacing it with a CLI keeps the correlation logic - the part worth learning - fully testable offline. This is the **Python substitution** described in the main README.

## Determinism rules

- Dictionaries are rebuilt from sorted `(count, key)` pairs rather than relying on `Counter` insertion order.
- Alerts sort by severity rank, then rule name, then detail.
- Timestamps are normalised to UTC. Naive timestamps are treated as UTC so host timezone settings cannot change an off-hours verdict.
- No `datetime.now()` call exists, so re-running the same fixture always gives the same result.

## Thresholds and false positives

A threshold is a policy choice, not a law. Five failed logins from one IP might be a burst or a shared NAT gateway. Real deployments tune these values against baseline data and pair them with allowlists; this lab only demonstrates the mechanism.
