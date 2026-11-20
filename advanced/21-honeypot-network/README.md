# 21 — Honeypot Network (Go/React/Docker → Python simulator/analyzer)

The upstream project is a Go/React/Docker honeypot network. This build substitutes a **Python simulator and analyzer**. It generates synthetic honeypot events and analyzes them for scanning, credential stuffing, and repeated source IPs. **There is no real listener, no container, no live target, and no real credential.** The offensive-sounding behaviors are represented only as simulated event records for defensive detection practice.

All example addresses come from documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Usernames are labels like `user-001`, and credential material is labeled only as `wordlist-a` or `wordlist-b` — never an actual secret.

## Run

```powershell
python honeypot.py sample
python honeypot.py sample --json
python honeypot.py analyze capture.json
```

`capture.json` can be a list or an object with an `events` key:

```json
{
  "events": [
    {"timestamp": "2026-02-03T09:00:00", "source_ip": "198.51.100.23", "service": "tcp-probe", "port": 4000, "event_type": "connect"},
    {"timestamp": "2026-02-03T09:04:00", "source_ip": "203.0.113.44", "service": "ssh", "port": 22, "event_type": "auth_failure", "username": "user-001", "credential_label": "wordlist-a"}
  ]
}
```

`sample` analyzes a deterministic capture containing three planted patterns. `sample --json` prints the raw synthetic events. `analyze` accepts thresholds such as `--scan-ports`, `--scan-window`, `--stuffing-usernames`, and `--repeated-events`.

## Detectors

- **Scanning**: at least N distinct destination ports from one source inside a sliding time window.
- **Credential stuffing**: at least N distinct synthetic usernames tried against one source with a low success ratio.
- **Repeated source**: one source producing at least N events overall.

Findings are sorted by severity, then kind, then source IP for stable output.

## Substitution notes

Go services, React UI, and Docker networking are replaced by pure Python event generation and analysis. No port is bound, no packet is sent, and no real username/password pair is handled.

## Test

```powershell
python -m unittest discover -s tests
```

10 tests, standard library only.
