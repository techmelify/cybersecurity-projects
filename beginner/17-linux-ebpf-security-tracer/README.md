# 17 — Linux eBPF Security Tracer (Python substitution)

Upstream uses eBPF/C to trace live events. This build analyzes synthetic JSON Lines events offline. No kernel hooks, no root, no live tracing.

## Run

```powershell
python tracer.py events.jsonl
```

Example event:

```json
{"type":"exec","comm":"bash","path":"/bin/bash","parent_comm":"nginx","uid":33}
```

## Detections

- Execution from `/tmp`, `/var/tmp`, or `/dev/shm`
- Web server spawning a shell or interpreter
- Root spawning curl/wget/shell
- Outbound connection to a public IP

## Test

```powershell
python -m unittest discover -s tests -v
```

7 tests, standard library only.
