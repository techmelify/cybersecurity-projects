# 18 — Nginx Edge Rule Engine (Python substitution)

Lua/Nginx upstream, replaced here with a standard-library Python rule evaluator. It evaluates nginx-like access rules from JSON for a synthetic request. No server is started and no network call is made.

## Run

```powershell
python edge_rules.py rules.json --path /api/admin --method POST --ip 203.0.113.5 --header X-Role=admin
```

Rules JSON:

```json
[
  {"name": "public", "action": "allow", "path": "/public/*", "method": "GET"},
  {"name": "admin", "action": "allow", "path": "/api/admin", "method": "POST",
   "cidr": "10.0.0.0/8", "header": ["X-Role", "admin"]},
  {"name": "deny-admin", "action": "deny", "path": "/api/admin"},
  {"name": "deny-all", "action": "deny"}
]
```

## Semantics

- Rules are evaluated top to bottom; the first match decides.
- `path` supports `"*"`, a trailing-wildcard prefix (`"/api/*"`), or an exact string.
- `method` is `"any"` or an explicit method (case-insensitive).
- `cidr` is checked with `ipaddress`; header names are case-insensitive, values are exact.
- No match means `deny` with rule name `default`. This is stricter than nginx's implicit allow, and is intentional for a lab evaluator.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only. IP addresses in fixtures come from documentation ranges.
