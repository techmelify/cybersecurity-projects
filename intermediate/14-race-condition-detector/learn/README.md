# Learn — TOCTOU and check-then-act

## What a race condition is

A race occurs when the outcome of an operation depends on the relative timing of events that the program does not control. In security work, the interesting case is usually two different actors touching the same resource.

## TOCTOU in one sentence

"Time of check to time of use": code verifies a condition (file does not exist, user is authorised, balance is sufficient), then acts on it later. If state changes between the check and the act, the decision may no longer be valid.

## Why the window matters

The gap between check and act is the opportunity for another subject to intervene. Shorter windows are harder to hit but not automatically safe; longer windows are easier to observe and exploit. Recording both phases in a log makes the window measurable.

## Defensive patterns

Reviewers look for atomic operations (create-with-exclusive flags, compare-and-swap, locks), re-validation immediately before use, and permission checks enforced at the resource itself rather than only in a wrapper.

## Scope of this tool

The analyzer only classifies data you provide. It performs no scheduling, no synchronisation primitives, and no interaction with real files or services. Findings are leads for a human reviewer.
