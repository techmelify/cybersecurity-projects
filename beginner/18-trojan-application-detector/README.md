# 18 — Trojan Application Detector (defensive substitution)

The upstream synopsis requested a trojan application *builder*. That capability is intentionally not implemented. This project detects trojan-like indicators in a JSON artifact snapshot instead.

## Run

```powershell
python detector.py apps.json
```

Snapshot format: `{"app-name": {"path": "file contents"}}`.

## Signals

- Execution primitives (`subprocess`, `os.system`, `shell=True`)
- Dynamic decoding/evaluation (`b64decode`, `eval`, `exec`)
- Persistence markers (Run key, crontab, `systemctl enable`)
- Known packers (low confidence alone)
- Execution + decoding + persistence together (high confidence)

## Test

```powershell
python -m unittest discover -s tests -v
```

6 tests. The tool analyses text only; it does not build, pack, or execute artifacts.
