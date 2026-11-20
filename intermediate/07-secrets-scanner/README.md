# 07 — Secrets Scanner (Python substitution)

**Upstream language: Go. This implementation is a Python substitution** because only the Python standard library is available on the build host. It reproduces the intended behavior — regex and entropy detection over a text snapshot — without Go tooling.

## Run

```powershell
python secrets_scanner.py config.yaml example.txt --json
python secrets_scanner.py example.txt
```

The CLI reads local text files only. Library callers provide a snapshot directly:

```python
from secrets_scanner import scan_snapshot

result = scan_snapshot({"app.cfg": "api_key = 'EXAMPLE'"})
```

## Checks

- AWS-like access key IDs (`AKIA`/`ASIA` plus 16 uppercase alphanumeric characters).
- PEM private key headers (RSA, EC, DSA, OpenSSH, encrypted).
- JWT-shaped three-segment base64url tokens.
- High-entropy tokens (configurable minimum length and Shannon entropy, mixed character classes).

Findings are masked before printing so a report cannot leak the value it found. Overlapping candidates are collapsed in favor of the specific pattern.

## Suppression

A line containing `nosec`, `pragma: allowlist secret`, or `secrets-scanner: ignore` suppresses findings on that line. A `secrets-scanner: disable-file` comment in the first ten lines suppresses the whole file. Markers are configurable through `ScanConfig`.

## Test

```powershell
python -m unittest discover -s tests -v
```

13 deterministic tests with synthetic strings; no real credentials or network access.

## Safety

Read-only analysis. No path is discovered implicitly by the library, and no secret is sent anywhere.
