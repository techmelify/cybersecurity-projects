# Learn — dependency trust signals

## What the graph models

A dependency graph has two kinds of records: **packages** (name, version, maintainers, time since last release) and **dependencies** (which package pulls in which). The analyzer keeps them separate so it can distinguish "this package looks risky" from "this edge points somewhere we cannot see".

## Why these three signals

1. **Typosquat-like names.** A name one edit away from a popular package can be chosen to catch mistakes. The detector compares against a `known_names` allowlist using edit distance and character-similarity ratio. It never downloads or registers a name.
2. **Unmaintained packages.** A large gap since the last release means fixes may not arrive. `last_release_days` is supplied as data, so no clock or registry lookup is needed.
3. **Unexpected maintainers.** A new maintainer outside the trusted set deserves review. The check only runs when `trusted_maintainers` is supplied; with no baseline there is nothing to compare against.

## Why the attack simulator became an analyzer

Building malicious packages would require packaging, distribution, and execution primitives that have no place in a learning repo. The **safety substitution** keeps the analytical half: understanding which metadata looks suspicious. This is the same reason no real registry is contacted.

## Design notes

- `edit_distance` uses one rolling row rather than a full matrix.
- Results are sorted by severity, rule, package, then detail for reproducible reports.
- Scores are capped at 100 to avoid meaningless large numbers.
- An unlisted dependency is flagged separately, because it is an evidence gap rather than a claim about the missing package.
