# Learn — API specification auditing

## Why audit the contract?

An OpenAPI document describes intended authentication, error shapes, and rate limits. Mistakes there tend to become real API behavior. Checking the contract is cheap, repeatable, and safe because it requires no running service.

## Effective security

Operations may declare their own `security`, inherit the document-level list, or explicitly opt out with `security: []`. A naive per-operation check either misses inherited auth or treats every inherited operation as secure. The scanner computes the effective value before judging write methods.

## Weak authentication signals

- `http` + `basic`/`digest`: credentials are reversible and often replayable.
- `apiKey` + `in: query`: keys end up in URLs, logs, and browser history.
- OAuth2 `implicit`: deprecated because access tokens are exposed in redirects.

## Verbose errors

Tracebacks and internal paths help an attacker map the backend. Examples and descriptions inside `responses` are enough to detect them statically; no error needs to be triggered.

## Exercises

- Add a check for missing `401`/`403` responses on protected operations.
- Detect wildcard CORS origins expressed through vendor extensions.
- Add SARIF output for CI integration.
