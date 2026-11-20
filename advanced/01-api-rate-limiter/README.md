# 01 — API Rate Limiter (Python substitution)

Upstream calls for a Redis-backed API rate limiter. This build replaces Redis
with a deterministic in-process simulation over synthetic request timestamps.
There is no server, no network stack, and no external service.

## Run

```powershell
# Supply synthetic arrival times directly.
python rate_limiter.py --timestamps 0,0,0.5,1.0,2.0 --capacity 2 --refill-rate 1 --limit 3 --window-seconds 2

# Or generate evenly spaced synthetic traffic.
python rate_limiter.py --generate 8 --start 0 --interval 0.25 --capacity 2 --refill-rate 1 --limit 3 --window-seconds 1

# Machine-readable report.
python rate_limiter.py --generate 8 --json
```

## Semantics

- **Token bucket:** starts full at the first request time; one token is spent
  per allowed request; tokens refill at `refill_rate` per second up to capacity.
- **Sliding window:** only allowed requests enter the window; an event exactly
  `window_seconds` old is expired. Requests are processed in timestamp order
  (stable for ties).
- Dropped requests are reported but never consume tokens or window slots.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only; offline and deterministic.
