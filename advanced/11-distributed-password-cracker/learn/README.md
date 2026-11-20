# Learn — workload partitioning and estimates

## Chunks

Splitting a list into fixed-size chunks gives each chunk an explicit `[start, end)` range. The ranges must cover every item exactly once; the tests check that property rather than only checking chunk count.

## Round-robin assignment

Assigning chunk `i` to worker `i % worker_count` is simple, deterministic, and balanced when chunks are similar in size. It is a teaching model, not a scheduler: real systems deal with stragglers, retries, and variable costs.

## Estimating work

`digest_operations = candidates * checks_per_candidate` and `bytes_hashed = sum(len(candidate bytes)) * checks_per_candidate`. These are bounded counts derived from the synthetic input. No timing is measured, so results never pretend to predict real hardware speed.

## Why no target comparison

Comparing digests against a captured hash is the part that makes an exercise an attack. This lab stops before that boundary: it generates synthetic strings, may hash them for illustration, and then reports counts.

## Exercises

- Add a weighted assignment strategy based on candidate length.
- Add a pure function that reports the maximum chunk imbalance across workers.
- Add a JSON snapshot of a plan and verify that a second run reproduces it byte for byte.
