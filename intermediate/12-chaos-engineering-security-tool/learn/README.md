# Learn — security chaos planning

## Simulate first

Chaos engineering is valuable when the blast radius is understood and rollback is rehearsed. A planning tool can compute that scope from declared services, users, regions, and data sensitivity without touching a system. Simulation events describe what *would* happen; they are not executors.

## Risk scoring

The score here is a transparent sum: fault severity, number of services, affected users, data sensitivity, and duration. Transparency matters more than a fancy model — a team can see which input pushed a scenario over budget and adjust the plan.

## Allowlisted fault types

A manifest is data, not code. Restricting `fault` to a known set prevents a typo or a malicious manifest from being interpreted as an arbitrary command name. The simulation only formats strings.

## Rollback as a first-class field

A scenario without rollback steps gets an explicit warning. Recording rollback per scenario also produces a reviewable checklist that can be used in a real, separately authorized drill.

## Exercises

- Add dependency edges between services to compute transitive blast radius.
- Export the plan as a table with owner and approval fields.
- Add a dry-run diff that shows expected configuration changes without applying them.
