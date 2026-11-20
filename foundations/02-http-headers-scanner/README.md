# 02 — HTTP Headers Scanner

Audit response headers for missing or weak security controls. Runs offline against a header file, or online against a target you own.

## Run

```powershell
python headers_scanner.py --file headers.txt
python headers_scanner.py https://your-lab.local
```

Header file format: one `Name: value` pair per line.

## Checks

| Control | PASS | WARN | FAIL |
|---|---|---|---|
| Content-Security-Policy | present | — | missing |
| Strict-Transport-Security | max-age ≥ 1 year | weak/invalid max-age | missing |
| X-Content-Type-Options | `nosniff` | — | missing/other |
| X-Frame-Options | DENY/SAMEORIGIN or CSP frame-ancestors | unexpected value | missing |
| Referrer-Policy | no-referrer or strict-origin-when-cross-origin | other value | missing |
| Permissions-Policy | present | missing | — |
| Server / X-Powered-By | not exposed | exposed | — |

Score: pass = 1, warn = 0.5, fail = 0. Maximum 8.

## Test

```powershell
python -m unittest discover -s tests -v
```

14 tests, standard library only, no network calls.

## Safety

The online mode only fetches headers from a URL you supply. Do not scan systems you do not own or have written permission to test.
