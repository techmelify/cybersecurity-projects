# 10 — Canary Token Generator (Python substitution)

Upstream specifies Go/React; this build is a Python CLI with a local JSON registry.

A canary token is a unique marker that should never be touched in normal use. If it appears in a log or request, that is a signal worth investigating.

## Run

```powershell
python canary.py tokens.json init
python canary.py tokens.json issue --note "lab document"
python canary.py tokens.json verify <token>
python canary.py tokens.json hit <token> --source 192.0.2.10
python canary.py tokens.json list
```

## Design

- Random 18-byte payload with an HMAC-SHA256 signature.
- Registry stores the SHA-256 digest of the full token, not the token.
- Hits are appended with timestamp, source, and user agent.

## Test

```powershell
python -m unittest discover -s tests -v
```

7 tests, standard library only.

## Safety

Tokens are local lab markers only. This tool does not create files, beacons, or network callbacks. Never use canary tokens to track people without authorisation.
