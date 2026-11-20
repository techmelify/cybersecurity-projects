# Learn — rate limiting algorithms

## Token bucket

A bucket holds up to `capacity` tokens. Each request consumes one token;
tokens accrue at a fixed rate. A full bucket permits a short burst, after
which the allowed rate converges to the refill rate. The simulation keeps the
token count as a float and refills only by elapsed synthetic time, so no real
clock is involved.

## Sliding window log

A sliding window keeps the timestamps of recently admitted requests. An event
at time `t` is admitted only when fewer than `limit` admitted events fall in
`(t - window, t]`. This is more precise than a fixed counter reset because a
burst straddling a boundary cannot double the effective rate.

## Why pure functions matter here

Real limiters depend on shared state and clocks, which makes tests flaky. By
passing timestamps in as data and returning decisions as data, every branch
(burst, refill, boundary expiry) can be exercised exactly. The CLI is only a
thin reporting layer over those pure evaluators.

## Exercises

- Add a fixed-window counter and compare its boundary behaviour.
- Add per-client identifiers and independent buckets per client.
- Feed the simulator from a deterministic Poisson-style timestamp generator.
