# Learn — compliance rules over snapshots

## Why a snapshot

A compliance check needs a stable input. Reading a JSON export makes each run reproducible and keeps the analyzer offline. The same rules can be applied to different snapshots without changing code.

## Separate detection from policy

`check_*` functions return `Finding` objects and do not decide what to do about them. The CLI applies `--fail-on` afterwards. This keeps the analysis reusable in tests, reports, or future dashboards.

## Reading the rules

- A public bucket can be identified by explicit flags, a public ACL, or a disabled access block. Write exposure is ranked above read exposure.
- IAM risk comes from the combination of effect, action, resource, and principal. A wildcard action scoped to one resource is less severe than a wildcard action on every resource for everyone.
- Encryption and logging controls are "declare explicitly" checks: a missing field is treated the same as a disabled one.

## Determinism

Findings are sorted by severity, rule ID, resource, and message. Counts and JSON keys are stable, which makes output suitable for tests and diffing.

## Exercises

- Add a rule for bucket versioning or MFA delete.
- Add `--min-severity` to filter displayed findings.
- Add a rule that flags IAM policies with no numeric condition or expiry.
