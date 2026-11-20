# Learn — DNS sinkholing

## Principle

A sinkhole maps unwanted domains to a dead address such as `0.0.0.0`. Requests fail locally instead of reaching the real service. This blocks ads, trackers, or known malicious domains.

## Hosts file vs DNS server

A hosts file is simple and works on one machine. A network sinkhole runs a DNS server for many clients and can log queries. This project implements the simpler hosts-file variant.

## Idempotence

Re-running a config tool should not create duplicates. Marking a managed block and replacing it wholesale makes the operation idempotent and keeps user edits outside the block intact.
