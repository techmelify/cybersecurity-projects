# Learn — authorisation-aware test planning

## Plan before touching anything

A safe assessment starts with a written scope: which assets are owned, which environment they live in, and which tests are permitted. The planner turns that scope into a checklist so the work stays inside agreed boundaries.

## Refusal is a feature

Three common boundary failures are handled explicitly:

1. **Out-of-scope target** — the target is not declared in the scope at all.
2. **Production asset** — the asset is declared but its environment or name marks it as production/live.
3. **Unauthorised test id** — the requested test is unknown or not listed in the scope.

Each failure produces a `Refusal` with a reason instead of a plan step. A test that points to an undeclared or production asset is also refused.

## Checklists map to categories

Each authorised test gets a short checklist appropriate to its category: read-only recon, configuration baseline comparison, safe scanning, or synthetic-account credential review. The rules of engagement remind the operator that authorisation, non-intrusive checks, and a stop-on-instability rule apply throughout.

## Why execute nothing

A planner is deliberately separate from any tooling. Keeping it pure — input mapping in, JSON plan out — makes it auditable, testable offline, and impossible for it to accidentally contact a system.
