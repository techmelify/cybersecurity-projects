# 13 — Credential Rotation Enforcer (Python substitution)

Crystal upstream, replaced here with a Python policy checker. It reads a JSON snapshot of credentials and reports entries older than the configured maximum age. No real credential store, vault, directory, or network endpoint is accessed.

## Run

```powershell
python rotation.py snapshot.json --as-of 2026-11-20
python rotation.py snapshot.json --as-of 2026-11-20 --max-age 30
```

Snapshot format:

```json
{
  "policy": {"max_age_days": 90},
  "credentials": [
    {"service": "example-api", "last_rotated": "2026-01-10", "owner": "team-a"},
    {"service": "example-db", "last_rotated": "2026-10-01", "owner": "team-b"}
  ]
}
```

## Semantics

- Age is whole days between `last_rotated` and `--as-of`. Passing `--as-of` makes runs deterministic.
- A credential is overdue only when `age_days > max_age_days`; the boundary is not overdue.
- Severity is `medium` when overdue by up to one policy window and `high` beyond that.
- `--max-age` overrides the snapshot policy for a one-off what-if check.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only. All credentials in fixtures are synthetic service names and dates; no secret values are present.
