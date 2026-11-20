# Learn — token buckets and sliding windows

## Two ways to say "too fast"

**Token bucket** models a budget that refills. A client accumulates up to `capacity` tokens and spends one per request. If tokens arrive at `rate` per second, a client can burst up to the capacity and then must wait for refills. This is good for absorbing short bursts.

**Sliding window** counts actual requests in the last `window` seconds. At most `limit` are allowed; older timestamps fall out of the deque. This gives a hard cap on request count over any interval of that length.

Neither algorithm is inherently better: the bucket shapes rate, the window enforces a count. Running both, as `simulate` does, shows how a request can be blocked by different properties.

## Why the simulation is offline

A live mitigation tool needs packet capture, sockets, and privileged network changes - none of which belong in a deterministic test. Replaying a synthetic log exercises the exact same decision logic with none of the operational risk. That is the **safety substitution** for this topic.

## Design notes

- Each client has independent state. `192.0.2.10` cannot consume `192.0.2.11`'s tokens.
- Requests are sorted before processing so shuffling a log does not change a verdict.
- Window expiry uses `<= cutoff`, making the boundary explicit and testable.
- Timestamps are synthetic floating-point seconds from the start of the simulation. They are never compared with the system clock.
- `generate_requests` uses `random.Random(seed)`, so the demo log is identical on every machine and Python version in the supported range.
