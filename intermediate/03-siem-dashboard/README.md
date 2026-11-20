# 03 — SIEM Dashboard

A local CLI that reads synthetic JSONL security events, aggregates counts, and raises rule-based alerts.

> **Python substitution:** the upstream project uses Flask plus React for a web dashboard. This version replaces that stack with a standard-library Python CLI. There is no web server, no browser, no database, and no live log source; `--json` provides the machine-readable output a frontend would have consumed. Deviation from upstream: visualisation is dropped in favour of deterministic text/JSON reports.

## Run

```powershell
python siem_dashboard.py events.jsonl
python siem_dashboard.py events.jsonl --json --threshold 3
```

Each line of `events.jsonl` is a JSON object. Recognised keys: `timestamp` (ISO-8601; alias `time`), `event_type` (alias `type`), `source_ip` (alias `ip`), `user`, `host`, `severity`, `message`. Missing fields get safe defaults.

## Alert rules

| Rule | Trigger | Severity |
|---|---|---|
| `failed_login_burst` | `failed_login` events from one source IP reach the threshold | high |
| `high_severity_events` | at least one `high`/`critical` event | high |
| `off_hours_activity` | events with an hour before 06:00 or from 22:00 reach the threshold | medium |
| `many_failed_users` | distinct non-unknown users in failed logins reach the threshold | medium |
| `firewall_block_burst` | `firewall_block` events reach the threshold | low |

`--threshold` defaults to 5. Aggregation dictionaries are sorted by descending count then key, and alerts by descending severity then rule name, so output is reproducible. No wall-clock time is read.

## Test

```powershell
python -m unittest discover -s tests -v
```

21 tests, standard library only, no network calls. All events are synthetic records created inside the tests.

## Safety

This tool only analyses a JSONL file you provide. It does not connect to log collectors, endpoints, or production SIEM systems. Counts and alerts are examples of correlation logic, not evidence about any real environment.
