# Learn — canary tokens

## Principle

A canary is a deliberate false asset. Because no legitimate workflow should touch it, any interaction is high-signal. Common examples are fake credentials in source code, unique document watermarks, and unused URLs.

## Why sign tokens

Randomness alone makes a token unguessable. The HMAC adds a second check: a tampered token is rejected before any registry lookup. Comparing signatures with `hmac.compare_digest` avoids timing leaks.

## Why store only a digest

If the registry leaks, plain tokens would let an attacker remove or replay them. Storing SHA-256 digests limits the damage. The secret used for signing is stored separately in the registry file; in production it should live in a secrets manager.

## Exercises

- Add expiry times to issued tokens.
- Add a webhook notifier for new hits.
- Export hits as CSV for a report.
