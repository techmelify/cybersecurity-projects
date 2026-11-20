<div align="center">
  <img src="assets/hero.svg" alt="Reverse Proxy Route Evaluator banner" width="100%" />
</div>

<br />

<div align="center">

# 🚦 Reverse Proxy Route Evaluator

![Tier](https://img.shields.io/badge/tier-ADVANCED-FBBF24?style=for-the-badge)
![Domain](https://img.shields.io/badge/domain-Routing%20Logic-4338CA?style=for-the-badge)
![Language](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-9%20passing-16A34A?style=for-the-badge)
![Deps](https://img.shields.io/badge/deps-standard%20library-gray?style=for-the-badge)

> **Decide the route. Never carry the traffic.** JSON rules choose an upstream or a deny — and no socket is ever opened.

</div>

---

## 🎯 What it does

The upstream project is a reverse proxy written in Haskell. This build is a **Python substitution that implements only a config-driven proxy ROUTE EVALUATOR**. It parses JSON routing rules for host, path, method, and headers, then selects an upstream or a deny decision. **It evaluates rules; it does not proxy traffic.** There are no sockets, listeners, HTTP clients, or servers.

### Routing semantics

- Routes are evaluated in order; the first match decides.
- `action` is `upstream` or `deny`; anything else is rejected. No match is a default `deny` with rule `default`.
- `host`: `*` or omission matches any host; names are case-insensitive and a client port is ignored when the route omits one.
- `path`: prefix match with a segment boundary, so `/api` matches `/api` and `/api/users` but not `/apixel`. `/` matches everything.
- `methods`: omission or an empty list means any method.
- `headers`: every listed header must be present; names are case-insensitive and value `*` means presence only.
- Only a matched `upstream` route exposes an upstream target in the decision.

## 🧠 How it works

```mermaid
flowchart LR
    R[Request<br/>host · path · method · headers] --> H{host match?}
    H -- no --> N[Try next route]
    H -- yes --> P{path prefix<br/>segment boundary?}
    P -- no --> N
    P -- yes --> M{method allowed<br/>or omitted?}
    M -- no --> N
    M -- yes --> HD{headers present<br/>and matching?}
    HD -- no --> N
    HD -- yes --> A{action?}
    A -- deny --> D[DENY<br/>route name]
    A -- upstream --> U[UPSTREAM target<br/>route name]
    N --> E{More routes?}
    E -- yes --> H
    E -- no --> FD[DENY default]
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

## 🚀 Quick start

```powershell
python route_evaluator.py routes.json --host app.local --path /api/users --method GET --header "X-Tenant=alpha" --header "X-Flag=any"
python route_evaluator.py routes.json --host app.local --path /admin
```

### Real output

```text
$ python route_evaluator.py $env:TEMP\proxy_routes.json --host app.local --path /api/users --method GET --header "X-Tenant=alpha" --header "X-Flag=any"
UPSTREAM backend-a:8080 (api)

$ python route_evaluator.py $env:TEMP\proxy_routes.json --host app.local --path /admin
DENY (admin-block)
```

## 📂 Project structure

```text
19-haskell-reverse-proxy/
├── assets/hero.svg              # generated visual identity
├── route_evaluator.py           # rule model + matcher + CLI
├── learn/README.md              # the concept notes
└── tests/test_route_evaluator.py  # 9 deterministic tests
```

## 🔍 Why it matters

- **Order is policy.** A broad catch-all route placed too early can shadow a specific deny.
- **Default deny** turns a missing rule into a safe decision.
- **Matching is observable.** Printing the rule name makes configuration debugging possible without touching a network.

### Substitution notes

The Haskell proxy implementation and its networking stack are replaced by pure Python rule evaluation. The CLI reads local JSON and prints a decision; it never forwards a request.

## 🧪 Tests

```powershell
python -m unittest discover -s tests
```

9 tests, standard library only: host/path/method/header matching, segment boundaries, first-match deny, default deny, wildcard and case handling, route loading validation, and the CLI.

## 📚 Learn more

Read [the concept notes](learn/README.md) for proxy routing semantics, first-match tables, and what a safety-only substitution keeps — and leaves out.

---

<div align="center">
  <sub>Part of <b>cybersecurity-projects</b> · Advanced tier · Python substitution, original implementation.</sub>
</div>
