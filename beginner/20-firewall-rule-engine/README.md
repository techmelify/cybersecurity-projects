# 20 — Firewall Rule Engine (Python substitution)

Upstream specifies V; this build is a Python first-match rule evaluator.

## Run

```powershell
python firewall.py rules.json --src 8.8.8.8 --dst 10.0.0.5 --port 443
```

Rules JSON:

```json
[
  {"name":"web","action":"allow","dst":"10.0.0.0/8","port":"80,443","protocol":"tcp"},
  {"name":"deny-all","action":"deny"}
]
```

## Semantics

- Rules are evaluated in order; the first match decides.
- Fields: `src`, `dst` (CIDR), `port` (`80`, `80-443`, or `80,443`), `protocol`.
- No match means default deny.

## Test

```powershell
python -m unittest discover -s tests -v
```

7 tests, standard library only.
