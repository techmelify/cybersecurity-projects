# 08 — API Security Scanner (Python substitution)

**Upstream stack: FastAPI + React, replaced by a Python CLI substitution.** Only the Python standard library is installed here, so both the web UI and the HTTP-based upstream approach are replaced by deterministic static analysis of a local JSON document. **No HTTP requests are made.**

## Run

```powershell
python api_security_scanner.py spec.json
python api_security_scanner.py spec.json --json --strict
```

## Checks

| Rule | Severity | Check |
| --- | --- | --- |
| SEC001 | high | Operations exist but no security scheme is declared. |
| SEC002 | high | A security requirement references an undefined scheme. |
| SEC003 | medium | Weak auth: HTTP basic/digest, API key in query, OAuth2 implicit. |
| SEC004 | medium | Response examples contain verbose error text (traceback, stack trace, debug mode, internal paths). |
| SEC005 | high | Write operation (`POST`/`PUT`/`PATCH`/`DELETE`) with no effective authentication. |
| SEC006 | low | No rate-limit description, `x-rate-limit`, or `429` response. |

Top-level `security` is inherited when an operation does not override it. An empty security object also counts as unauthenticated.

## Test

```powershell
python -m unittest discover -s tests -v
```

14 deterministic tests using synthetic specifications. `--strict` returns exit code 1 when findings exist, which makes the scanner usable in a pipeline.

## Safety

Static analysis only. The tool reads one local JSON file; it never resolves hosts, sends requests, or modifies the specification.
