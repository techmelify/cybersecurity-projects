# Learn — username enumeration detection

## The underlying leak

A login form can confirm whether an account exists even when it refuses to authenticate. The leak appears as a different status code, a different error string, or a measurable timing difference (for example, hashing a real password versus returning early for an unknown user).

## Why compare failures only

Successes are intentionally different from failures. Comparing them would always produce a finding. The useful question is whether two *failed* attempts behave differently solely because the usernames differ.

## Median over mean

A few slow requests (garbage collection, network jitter) distort the arithmetic mean. The median per username is more stable, and an absolute-delta check prevents a tiny but proportionally large difference from being reported.

## Defensive framing

Enumeration tooling tests a target. This project does the opposite: it audits recorded outcomes so a team can fix a leaky endpoint. The dataset is plain result metadata — no passwords are stored or displayed.

## Exercises

- Compare per-user message entropy across a larger sample.
- Add a known-valid-user list to label which side of a timing split is leaking account existence.
- Recommend uniform responses and constant-work hashing based on the detected signal.
