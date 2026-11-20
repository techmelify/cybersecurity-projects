# Learn — credential rotation policy checks

## Why rotation ages matter

A secret that stays in place for a long time has more opportunities to leak, be copied, or outlive the account it belongs to. Rotation policy converts a vague goal ("rotate regularly") into a measurable rule: a maximum age in days.

## Age, not calendar date

Comparing a rotation date against a fixed "today" makes output reproducible. An explicit `as_of` argument is preferable to reading the system clock inside a pure function, because it lets tests assert exact ages.

## Boundary conditions

"Older than 90 days" means `age > 90`, not `age >= 90`. Off-by-one errors at the boundary are a common source of noisy compliance reports.

## Escalation

Not all overdue items are equal. Escalating severity once a secret has been stale for more than twice the policy window helps owners triage the worst cases first.

## Safety

An inventory checker should consume metadata only: service name, owner, and rotation date. It never needs secret material, and this implementation performs no I/O beyond reading the caller's snapshot file.
