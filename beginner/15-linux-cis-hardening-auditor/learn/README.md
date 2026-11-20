# Learn — configuration hardening

## CIS benchmarks

CIS benchmarks are consensus checklists for secure configuration. They cover services, authentication, kernel parameters, and logging. This project implements a small representative subset.

## Why snapshot-based

A live hardening check depends on the host, privileges, and distro layout. Feeding it a snapshot makes the logic deterministic and testable. The same engine can later be pointed at real files.

## Status semantics

`pass` means the setting is correct. `fail` means it is present and wrong. `warn` means the data was missing or the setting is risky but not conclusive. This avoids treating "not measured" as "bad".
