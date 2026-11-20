# Learn — parsing saved scan output safely

## Stateless means no active probing

A stateless scanner in this lab is a parser, not a network client. It consumes
text that was produced elsewhere and previously saved. That makes it safe to
run in a classroom: no packets leave the machine and no target is touched.

## Anchored regular expressions

Host blocks are recognised only by the exact `Nmap scan report for ...` prefix.
Port rows require a numeric port, a protocol, a state, and a service. Anchoring
with `^`/`$` plus stripping whitespace prevents the `PORT STATE SERVICE`
header or arbitrary commentary rows from becoming fake findings.

## Immutable findings

`HostFinding` and `PortFinding` are frozen dataclasses. Parsing collects data
into temporary lists and returns tuples, so downstream risk matching cannot
accidentally mutate the parsed report.

## Catalog matching

A catalog entry with no `ports` list matches that service on any port; an entry
with a port set is narrower. Severity ranks keep filtering deterministic, and
only `open` ports become risks, so filtered/closed rows remain visible in the
parsed report without creating alerts.

## Exercises

- Add parsing for `MAC Address:` and OS guess rows.
- Add a catalog deduplication pass for overlapping entries.
- Add a `--show-all` flag that prints closed and filtered ports explicitly.
