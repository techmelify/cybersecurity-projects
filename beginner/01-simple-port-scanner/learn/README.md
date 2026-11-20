# Learn — TCP connect scanning

## How it works

`asyncio.open_connection` performs a TCP three-way handshake. If it completes, the port is open. If it refuses, times out, or errors, the port is treated as closed. This is a *connect scan*: it is reliable and needs no privileges, but it is logged by the target and is slower than a SYN scan.

## Concurrency

A bare sequential scan of 65,535 ports would be far too slow. `asyncio.gather` launches all attempts, while a `Semaphore` caps how many are in flight. The cap matters: too many simultaneous connections exhaust local sockets and produce false negatives.

## Deterministic tests

The test suite binds a listener to `127.0.0.1` on an OS-assigned port. That gives a guaranteed-open port without depending on any external service. A second, immediately-closed ephemeral port provides a reliable closed case.

## Exercises

- Add `--json` output.
- Add IPv6 support.
- Compare timing at concurrency 10 vs 100 vs 500.
