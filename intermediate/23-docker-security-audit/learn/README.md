# Learning notes — container configuration review

## What the audit looks for

- **Root user**: if no `USER` is declared, the container typically starts as root. An explicit `USER root` is even clearer.
- **Privileged mode**: a broad setting that removes many isolation boundaries. Prefer narrow capabilities.
- **Host mounts**: binding host paths into a container widens the blast radius. Docker socket mounts are especially sensitive.
- **Mutable tags**: `:latest` (or no tag) makes builds non-reproducible. Prefer version pins or digests.
- **Inline secrets**: credentials placed in `ENV`, `ARG`, or config can leak through image layers, logs, and source control.

## Why text-only is useful

A text snapshot makes reviews deterministic and safe. You can teach the same
checks without a daemon, without privileged access, and without real
credentials. Findings are indicators to discuss with the image owner, not
automatic proof of compromise.

When remediating, use runtime secret injection, explicit non-root users, narrow
capabilities, named volumes, and pinned image references.
