# Learn — what a token inspector can and cannot tell you

## Anatomy of a JWT-like string

Three dot-separated segments: `header.payload.signature`. The first two are base64url-encoded JSON. The third is an opaque signature marker in this lab. Decoding the first two segments is not verification - anyone can write arbitrary JSON there. That is why the tool reports structural and claim-level findings only.

## Claim checks explained

- **exp** (expiration): a token whose `exp` timestamp is not in the future should be rejected.
- **iat** (issued at): a value ahead of `now` suggests clock skew or a manipulated token. `iat >= exp` is internally inconsistent.
- **aud** (audience): the intended recipient. A mismatch means the token was meant for another service.
- **iss** (issuer): compared against an explicit allowlist supplied with `--trusted-issuer`.
- **alg: none**: some libraries historically accepted `none` and skipped signature verification, so a token claiming it is a strong signal of tampering.
- **lifetime**: very long-lived tokens widen the window of misuse if leaked.

## Why no signing code

Signing and forging use the same primitives. This lab deliberately stops at inspection: the **safety substitution** is to learn how bad tokens look without learning how to make them. Base64url decoding is a parsing step, not a weakness.

## Design notes

- All timestamps are UTC; naive `--now` values are interpreted as UTC.
- Supplying `now` explicitly turns the checks into a pure function of the input.
- The verdict aggregates severities, but individual findings are always returned so a reviewer can see *why*.
- No secret is read, derived, or stored, and no network request is made.
