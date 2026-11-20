# 20 — “Monitor the Situation” Dashboard (Go/React → Python CLI)

The upstream project is a Go/React situation dashboard. This build substitutes a **Python command-line dashboard** that aggregates synthetic event feeds into a console report. **No live data sources, listeners, or web server are used.** Input is a local JSON file or the built-in deterministic sample generator.

## Run

```powershell
python dashboard.py --sample
python dashboard.py events.json --top 3 --bucket-minutes 30
```

`events.json` can be a list or an object with an `events` key:

```json
{
  "events": [
    {"timestamp": "2026-01-12T08:01:00", "source": "auth-gateway", "severity": "high", "category": "auth", "message": "threshold crossed"},
    {"timestamp": "2026-01-12T08:14:00Z", "source": "ids-edge-01", "severity": "low", "category": "network", "message": "policy matched"}
  ]
}
```

The report prints severity counts with ASCII bars, top event sources ranked by count, and timeline buckets with empty periods shown as zero. `--sample` generates 48 reproducible synthetic events with a fixed seed; use `--top` and `--bucket-minutes` to adjust aggregation.

## Semantics

- Severity names are normalized to lowercase and ordered `critical`, `high`, `medium`, `low`, `info`; unknown values sort after these by name.
- Sources are sorted by descending count, then alphabetically, so ties are deterministic.
- Timestamps accept ISO-8601 forms, including trailing `Z`. Buckets are floored to `--bucket-minutes` boundaries and filled from the first to the last event bucket.
- `elevated` is the total of `critical` and `high` events.

## Substitution notes

Go services and the React web UI are replaced by a single Python CLI writing plain text to stdout. Synthetic feeds stand in for live telemetry; nothing is collected from hosts or the network.

## Test

```powershell
python -m unittest discover -s tests
```

9 tests, standard library only.
