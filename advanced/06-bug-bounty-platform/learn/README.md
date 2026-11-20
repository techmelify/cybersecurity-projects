# Learn — finding triage and scoring

## CVSS-like, not CVSS

The score uses the familiar exploitability/impact structure with fixed weights
for attack vector, complexity, privileges, user interaction, scope, and
confidentiality/integrity/availability. It is useful for practising consistent
triage, but it is deliberately labelled CVSS-like because a real assessment
needs the official specification and careful environmental metrics.

## Why a workflow matters

A finding is not just a score. `open`, `triaged`, `in_progress`, `fixed`,
`closed`, and `wont_fix` communicate who needs to act next. Restricting
transitions keeps the exported report internally consistent; reopening is
allowed from most states because fixes can regress.

## Immutable findings

`Finding` and `CvssVector` are frozen. A status change returns a new object via
`transition`, and the tracker saves atomically. That makes it hard to mutate a
finding in one code path and leave the file system unaware.

## Local-only substitute

A production bounty platform needs authentication, tenant isolation, review
queues, and an audit log. None of that is simulated here. The CLI exists to
practise scoring and workflow reasoning on synthetic findings only.

## Exercises

- Add an auditor field and reject self-closing findings.
- Add a report grouped by target instead of severity.
- Add a reopen reason that is stored with the status change.
