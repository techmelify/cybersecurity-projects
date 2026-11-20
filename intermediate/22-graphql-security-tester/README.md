# 22 — GraphQL Security Tester (Python offline analyzer)

This is a **Python offline query analyzer**. It reads GraphQL query text and a
declared server policy from a JSON snapshot. There is no live endpoint, no HTTP
client, and no network access.

## Run

```powershell
python graphql_analyzer.py snapshot.json
python graphql_analyzer.py snapshot.json --json
```

Snapshot (synthetic queries):

```json
{
  "queries": [
    {"name": "dashboard", "query": "query dashboard { user { id posts { title } } }"}
  ],
  "server_policy": {
    "max_depth": 8,
    "max_aliases": 10,
    "max_batch_size": 5
  }
}
```

Queries may also be plain strings. `server_policy.max_depth` is used to detect
missing or overly permissive depth limits.

## Checks

- `GQL-001`: selection depth above 8.
- `GQL-002`: `__schema` or `__type` introspection fields.
- `GQL-003`: more than 10 aliases in one query.
- `GQL-004`: more than 5 operations in the supplied batch.
- `GQL-005`: server depth limit missing/non-positive (high) or above 20 (medium).

Braces inside strings and comments are ignored by the small built-in tokenizer.

## Test

```powershell
python -m unittest discover -s tests
```

8 deterministic tests. This tool reports risk indicators; it does not send queries anywhere.
