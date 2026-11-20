# 06 — Bug Bounty Platform (Python CLI substitution)

Upstream specifies FastAPI plus React. This build replaces the web stack with
a Python CLI and one local JSON file. There is no web UI, no HTTP server, no
accounts, and no network access.

## Run

```powershell
python finding_tracker.py findings.json add F-001 "Reflected input" "https://lab.example/search" --description "Lab-only finding" --c high --i low
python finding_tracker.py findings.json list
python finding_tracker.py findings.json status F-001 triaged
python finding_tracker.py findings.json status F-001 in_progress
python finding_tracker.py findings.json export report.json
python finding_tracker.py findings.json list --json
```

Vector flags mirror the eight CVSS-like inputs: `--av`, `--ac`, `--pr`, `--ui`,
`--scope`, `--c`, `--i`, `--a` with safe lab defaults. Scores are a teaching
approximation inspired by CVSS v3.1; they are **not official CVSS scores**.

## Workflow

`open -> triaged -> in_progress -> fixed -> closed`, with `wont_fix` reachable
from `open`/`triaged` and `open` reachable from most states to allow reopening.
Invalid transitions are rejected. Severity bands: 9.0+ critical, 7.0+ high,
4.0+ medium, above 0 low, 0 none.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only; offline and deterministic.
