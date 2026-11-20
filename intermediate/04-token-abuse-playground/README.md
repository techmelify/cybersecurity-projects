# 04 — Token Abuse Playground (inspector)

An offline, parse-only inspector for synthetic JWT-like token strings.

**Safety substitution:** the upstream topic covers abusing tokens. This project implements the defensive counterpart only. It parses tokens, checks `exp`, `iat`, `aud`, `iss`, and flags weak `alg: none`. It does **not** forge tokens, sign them, brute-force secrets, bypass verification, or contact any service. Signature segments are treated as opaque text and are never cryptographically verified.

> **Python substitution:** the upstream implementation is replaced with a standard-library-only Python CLI. The lab uses synthetic three-segment strings produced inside the tests, so no real credentials or production tokens are involved.

## Run

```powershell
python token_inspector.py --token "<header>.<payload>.<signature>" --now 2026-11-20T00:00:00Z
python token_inspector.py --file token.txt --json --expect-aud lab-api --trusted-issuer https://issuer.example.test
```

`parse_token(token)` decodes the base64url header and payload into dictionaries. `inspect_token(token, now=..., expected_aud=..., trusted_issuers=...)` returns an immutable `Inspection` with findings and a verdict. If `now` is omitted, time-based checks are skipped and a `time_reference_missing` finding is added.

## Checks

| Code | Severity | Meaning |
|---|---|---|
| `alg_none` | critical | header declares `alg: none` |
| `alg_missing` | high | no algorithm declared |
| `unsigned_token` | high | empty third segment |
| `expired` / `exp_missing` / `exp_invalid` | high / medium / medium | expiry problems |
| `iat_in_future` / `iat_missing` / `iat_invalid` | medium / low / medium | issued-at problems |
| `iat_after_exp` / `long_lifetime` | medium / low | claim consistency and lifetime |
| `aud_mismatch` / `aud_missing` | high / medium | audience problems |
| `iss_untrusted` / `iss_missing` | high / medium | issuer problems |
| `time_reference_missing` | low | no `--now` supplied |

Verdict is `reject` for any critical/high finding, `review` for medium only, otherwise `allow`. Findings keep a fixed order, so reports are reproducible.

## Test

```powershell
python -m unittest discover -s tests -v
```

27 tests, standard library only, no network calls. All tokens are synthetic test fixtures.

## Safety

Inspect only tokens you are authorised to review. A clean report does not prove a token is genuine - this tool never verifies signatures and makes no claim of cryptographic authenticity.
