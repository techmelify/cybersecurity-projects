# 12 — Kernel Rootkit Detection

Heuristic analysis of a synthetic syscall-table snapshot for rootkit-style indicators.

## Substitution

The upstream Rust project is replaced by a Python standard-library CLI. There is no kernel access: the tool never reads kernel memory, loads modules, opens `/proc`, or inspects a live system. It only parses the JSON snapshot supplied to it.

## Detections

- `KRN-HOOK-001` — handler differs from the snapshot's expected handler
- `KRN-MOD-001` — syscall owner is outside the snapshot's `allowed_modules`
- `KRN-PROC-001` — process marked hidden or absent from the proc/ps views in the snapshot

## Snapshot shape

```json
{
  "allowed_modules": ["kernel", "ext4"],
  "syscalls": [
    {"number": 1, "name": "write", "handler": "sys_write",
     "expected_handler": "sys_write", "module": "kernel"}
  ],
  "processes": [
    {"pid": 1, "name": "init", "visible_in_proc": true,
     "listed_by_ps": true, "hidden": false}
  ]
}
```

## Run

```powershell
python syscall_snapshot_analyzer.py snapshot.json
python syscall_snapshot_analyzer.py snapshot.json --json
python syscall_snapshot_analyzer.py snapshot.json --fail-on critical
```

## Test

```powershell
python -m unittest discover -s tests
```

14 tests. Standard library only.

## Limitations

A snapshot can be stale or forged, and a clean result does not prove a real kernel is healthy. This is a teaching exercise in comparing expected versus observed metadata, not a production rootkit detector.
