# Learning notes — privilege indicators

This project teaches **detection and hardening**, not exploitation.

## Concepts

- **Setuid bit (`0o4000`)**: a file marker that can change how an executable is run. Auditors look for setuid files that are writable by others, owned by unexpected accounts, or reachable through writable directories.
- **Sticky bit (`0o1000`)**: on a shared directory, it restricts who may remove entries. A world-writable directory without it deserves review.
- **Sudoers rules**: broad grants (`ALL`, command wildcards, `NOPASSWD`) increase impact if an account is compromised. `env_reset` limits inherited environment variables.
- **Path overlap**: a privileged executable located under a writable directory is a higher-value indicator than either fact alone.

## Defensive workflow

1. Take a read-only inventory; never modify the system while auditing.
2. Normalize modes and compare them against expected baselines.
3. Report each indicator with a concrete, non-offensive remediation.
4. Track findings over time to spot drift.

Only synthetic fixtures are used here. Do not point this tool at systems you do not own or administer.
