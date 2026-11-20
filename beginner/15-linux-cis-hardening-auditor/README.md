# 15 — Linux CIS Hardening Auditor (Python substitution)

Upstream specifies Bash; this build is Python. It audits a JSON snapshot read-only.

## Run

```powershell
python cis_audit.py snapshot.json
```

Snapshot format:

```json
{
  "files": {"/etc/ssh/sshd_config": "PermitRootLogin no\n"},
  "modes": {"/etc/shadow": 0}
}
```

## Checks

- SSH root login and password authentication
- `/etc/shadow` and `/etc/passwd` permissions
- Core dump limit
- IPv4 forwarding

## Test

```powershell
python -m unittest discover -s tests -v
```

5 tests. The auditor never writes to the snapshot or to a live system.
