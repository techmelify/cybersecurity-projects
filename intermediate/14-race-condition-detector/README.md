# 14 — Race Condition Detector (defensive substitution)

The upstream synopsis asked for a race-condition exploiter. That capability is intentionally not implemented. This project is a **defensive substitution**: it detects check-then-act (TOCTOU) risk in synthetic access logs and code snippets. It does not trigger, time, or exploit any race.

## Run

```powershell
python race_detector.py timeline events.json --window 5
python race_detector.py code sources.json
```

`events.json` is a list of records with `timestamp` (ISO-8601), `subject`, `resource`, and `phase` (`check` or `act`):

```json
[
  {"timestamp": "2026-01-01T00:00:00", "subject": "alice", "resource": "/tmp/report", "phase": "check"},
  {"timestamp": "2026-01-01T00:00:01", "subject": "bob", "resource": "/tmp/report", "phase": "act"}
]
```

`sources.json` maps a label to source text: `{"app.py": "if os.path.exists(p):\n    open(p)\n"}`.

## Detection

- **Timeline:** an `act` on the same resource by a *different* subject within the window after a `check` is reported. Smaller gaps score `high`; larger gaps score `medium`.
- **Code:** a check call (`exists`, `access`, `stat`, `check`) followed within three lines by an act call (`open`, `write`, `delete`, `unlink`, `remove`, `replace`) is reported as `medium`.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only; every fixture is synthetic. This is a heuristic review aid, not proof that a vulnerability exists.
