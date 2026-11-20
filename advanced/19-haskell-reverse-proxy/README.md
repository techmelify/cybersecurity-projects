# 19 — Haskell Reverse Proxy (Python substitution)

The upstream project is a reverse proxy written in Haskell. This build is a **Python substitution that implements only a config-driven proxy ROUTE EVALUATOR**. It parses JSON routing rules for host, path, method, and headers, then selects an upstream or a deny decision. **It evaluates rules; it does not proxy traffic.** There are no sockets, listeners, HTTP clients, or servers.

## Run

```powershell
python route_evaluator.py routes.json --host app.local --path /api/users --method GET --header "X-Tenant=alpha" --header "X-Flag=any"
```

`routes.json` may be a list or an object with a `routes` key:

```json
{
  "routes": [
    {
      "name": "api",
      "action": "upstream",
      "host": "app.local",
      "path": "/api",
      "methods": ["GET", "POST"],
      "headers": {"X-Tenant": "alpha", "X-Flag": "*"},
      "upstream": "backend-a:8080"
    },
    {"name": "admin-block", "action": "deny", "host": "app.local", "path": "/admin"},
    {"name": "site", "action": "upstream", "path": "/", "upstream": "backend-b:8080"}
  ]
}
```

Example output: `UPSTREAM backend-a:8080 (api)` or `DENY (admin-block)`.

## Semantics

- Routes are evaluated in order; the first match decides.
- `action` is `upstream` or `deny`; anything else is rejected. No match is a default `deny` with rule `default`.
- `host`: `*` or omission matches any host; names are case-insensitive and a client port is ignored when the route omits one.
- `path`: prefix match with a segment boundary, so `/api` matches `/api` and `/api/users` but not `/apixel`. `/` matches everything.
- `methods`: omission or an empty list means any method.
- `headers`: every listed header must be present; names are case-insensitive and value `*` means presence only.
- Only a matched `upstream` route exposes an upstream target in the decision.

## Substitution notes

The Haskell proxy implementation and its networking stack are replaced by pure Python rule evaluation. The CLI reads local JSON and prints a decision; it never forwards a request.

## Test

```powershell
python -m unittest discover -s tests
```

9 tests, standard library only.
