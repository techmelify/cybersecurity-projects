# 10 — Credential Enumeration Detector (defensive substitution)

**Upstream synopsis was offensive (credential enumeration). This project is a defensive substitution:** it detects enumeration-observable behavior in an already-recorded dataset of login results. **It does not send login requests, guess passwords, or contact any service.**

## Run

```powershell
python credential_enumeration_detector.py results.json
python credential_enumeration_detector.py results.json --json --strict
```

Input is a JSON list of records:

```json
[
  {"username": "alice", "outcome": "failure", "status_code": 401,
   "message": "Invalid credentials", "duration_ms": 48.5}
]
```

No passwords or other secrets belong in this dataset.

## Signals

| Kind | Severity | Meaning |
| --- | --- | --- |
| `status_code_differential` | high | Failed attempts return different HTTP codes for different usernames. |
| `message_differential` | high | Failed attempts return different normalized messages for different usernames. |
| `timing_differential` | medium | Failure response times form a slow/fast split beyond the configured ratio and absolute delta. |

Only `failure`, `invalid`, and `locked` outcomes are aggregated; successful logins are ignored. A username needs at least two observations by default, and at least two usernames are required before comparisons are made.

## Test

```powershell
python -m unittest discover -s tests -v
```

14 deterministic tests using synthetic result records.

## Safety

Pure offline analysis of caller-supplied data. There is no HTTP client, no socket usage, and no credential handling.
