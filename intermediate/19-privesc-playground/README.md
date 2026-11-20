# 19 — Privilege Escalation Indicator Auditor (defensive substitution)

The upstream synopsis is an offensive "Privesc Playground". This build is a
**defensive substitution**: it reads a synthetic system snapshot and reports
risky privilege paths. It does not provide exploitation steps, execute
commands, or touch a live system.

## Run

```powershell
python privesc_audit.py snapshot.json
python privesc_audit.py snapshot.json --json
```

Snapshot format (all paths and values are synthetic):

```json
{
  "suid_files": [
    {"path": "/opt/team/helper", "owner": "root", "mode": "4755"}
  ],
  "sudoers_lines": [
    "Defaults env_reset",
    "alice ALL=(ops) /usr/bin/true"
  ],
  "world_writable_dirs": [
    {"path": "/tmp", "mode": "1777"}
  ]
}
```

Modes are octal strings (or integers written as octal digits).

## Checks

- `SUID-001/002/003`: root-owned world-executable setuid, writable setuid, non-root setuid owner.
- `SUDO-001/002/003/004`: broad passwordless rules, unrestricted command sets, wildcards, missing `env_reset`.
- `DIR-001/002`: world-writable directories without a sticky bit, and setuid paths beneath writable directories.

Every finding includes a high-level remediation note. No exploit commands are produced.

## Test

```powershell
python -m unittest discover -s tests
```

7 deterministic tests. The auditor only reads the JSON file passed on the command line.
