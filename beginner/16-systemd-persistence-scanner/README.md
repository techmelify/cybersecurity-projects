# 16 — Systemd Persistence Scanner (Python substitution)

Upstream specifies Go; this build is a read-only Python scanner for systemd unit definitions.

## Run

```powershell
python systemd_scan.py units.json
```

Snapshot format: `{"name.service": "[Service]\nExecStart=...\n"}`.

## Signals

- Executable paths under `/tmp`, `/var/tmp`, or `/dev/shm`
- `curl`, `wget`, `base64 -d`, inline interpreters, or shell `-c`
- Root user combined with a writable-path executable
- `Restart=always` on a unit that already has findings

## Test

```powershell
python -m unittest discover -s tests -v
```

6 tests, standard library only. No live unit files are read or modified.
