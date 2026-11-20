# 23 — Docker Security Audit (Go → Python substitution)

Upstream is Go; this build is a **Python substitution**. It parses a Dockerfile
and compose-like config **text snapshot** and flags container hardening
indicators. There is no Docker daemon access, no image build, and no container
execution.

## Run

```powershell
python docker_audit.py snapshot.json
python docker_audit.py snapshot.json --json
```

Snapshot (all values are synthetic):

```json
{
  "dockerfile": "FROM alpine:3.19\nUSER 10001\n",
  "config": "services:\n  app:\n    image: alpine:3.19\n    privileged: false\n"
}
```

Use `config` or `compose` as the key for the config text.

## Checks

- `DOCK-001`: explicit root user (high) or no user declared (medium).
- `DOCK-002`: privileged mode enabled in config or flags.
- `DOCK-003`: host bind mounts; sensitive host paths such as `/var/run/docker.sock` are high severity.
- `DOCK-004`: `:latest` tags and implicit latest tags; digest pins are ignored.
- `DOCK-005`: inline secret-like keys in `ENV`, `ARG`, or config. **Values are never printed.**

## Test

```powershell
python -m unittest discover -s tests
```

8 deterministic tests. Only text is parsed; no real credentials or daemon access are used.
