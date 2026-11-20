# 06 — DDoS Mitigation Simulator

A traffic-shaping simulator that replays a synthetic request log through two classic rate-limiting algorithms.

**Safety substitution:** the upstream synopsis is a live DDoS mitigation tool. This project performs no live capture, opens no sockets, sends no traffic, and changes no firewall or router state. It only reads a local JSONL log (or generates a deterministic demo log) and reports which requests the algorithms would have allowed or dropped.

> **Python substitution:** the upstream implementation is replaced by a standard-library-only Python CLI. All client addresses are documentation/test addresses from `192.0.2.0/24` and every request is synthetic.

## Run

```powershell
python traffic_shaper.py --demo --count 20 --json
python traffic_shaper.py --log requests.jsonl --capacity 5 --rate 1 --window-limit 10 --window 60
```

Each JSONL line has `time` (synthetic seconds), `client`, and optional `path`:

```json
{"time": 0.0, "client": "192.0.2.10", "path": "/login"}
```

## Algorithms

- **Token bucket:** each client starts with `capacity` tokens (or `--initial-tokens`) and regains `rate` tokens per second, up to capacity. A request needs one whole token. Bursts up to the capacity are allowed; sustained load is limited by the refill rate.
- **Sliding window:** at most `window-limit` requests per client in the last `window` seconds. Timestamps at or before `time - window` are expired.
- **Combined:** a request is allowed only if both algorithms allow it. The report names which algorithm blocked each dropped request.

Requests are processed in `(time, client, path)` order, so input line order does not change the result. No wall-clock time is read.

## Test

```powershell
python -m unittest discover -s tests -v
```

22 tests, standard library only, no network calls. The demo log is generated with a fixed seed.

## Safety

This is an educational simulation. Real mitigation needs accurate time sources, distributed state, careful allowlists, and operational oversight; none of that is modelled here. Do not use this tool against live traffic or infrastructure.
