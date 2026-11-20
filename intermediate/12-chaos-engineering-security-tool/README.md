# 12 — Chaos Engineering Security Tool (Python substitution)

**Upstream language: Go. This implementation is a Python substitution** using only the standard library. It preserves the planning and reporting behavior while replacing Go's concurrency and CLI stack with immutable dataclasses and a simple `argparse` interface.

**Safety boundary:** the tool plans and *simulates* security-focused fault scenarios. **Disruption is never executed.** There is no subprocess, socket, or service client in the implementation.

## Run

```powershell
python chaos_engineering_security_tool.py plan.yaml
python chaos_engineering_security_tool.py plan.json --json --max-risk 70
```

Manifests may be JSON or a small YAML-like subset (indented mappings, `- ` list items, inline `[a, b]` lists and `{key: value}` maps, quoted strings, and `#` comments). PyYAML is not required.

```yaml
scenarios:
  - id: tls-regression
    target: staging-api
    fault: tls_config_regression
    duration_seconds: 90
    blast_radius:
      services: [gateway, auth]
      users: 40
      data_sensitivity: high
    rollback:
      - restore_config
      - restart_gateway
```

Supported fault types are an explicit allowlist: `auth_delay`, `tls_config_regression`, `firewall_rule_misconfiguration`, `token_expiry_skew`, `rate_limit_disabled`, `logging_drop`. Unknown faults are rejected.

## Output

- Risk score per scenario from fault severity, service count, user count, data sensitivity, and duration (capped at 100).
- Simulated timeline phases: `plan`, `simulate`, `verify`, `rollback`.
- Blast-radius statement and a deduplicated rollback plan.
- Warnings for scenarios above the risk budget or without rollback steps.

`--max-risk` sets the budget; the CLI returns exit code 1 when a scenario exceeds it.

## Test

```powershell
python -m unittest discover -s tests -v
```

17 deterministic tests with synthetic manifests.

## Safety

Planning and simulation only. No scenario has an executor, and no command derived from a manifest is ever run.
