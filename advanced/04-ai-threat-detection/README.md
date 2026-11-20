# 04 — AI Threat Detection (transparent statistical substitution)

Upstream calls for a PyTorch-style AI detector. This build uses **no PyTorch
and no machine-learning framework**. It is an explainable statistical detector
over synthetic feature vectors: in-memory z-scores plus a few explicit
threshold rules. No model file is trained, saved, or loaded.

## Run

```powershell
# Built-in synthetic baseline and events.
python threat_detector.py --demo
python threat_detector.py --demo --json --suspicious-only

# Your own synthetic JSON lists.
python threat_detector.py --baseline baseline.json --events events.json --z-threshold 2.5
```

Baseline and events share this shape:

```json
[
  {"event_id": "e1", "features": {"failed_logins": 1, "bytes_out": 1200, "admin_actions": 0}}
]
```

Optional `--rules rules.json` accepts objects such as
`{"name":"burst","feature":"failed_logins","above":5,"score":3,"reason":"login burst"}`.

## Detection logic

- A baseline mean and population standard deviation are computed in memory
  from at least two synthetic normal vectors.
- Each event feature gets `z = (value - mean) / stddev`. A zero standard
  deviation yields `0` for an equal value and a capped `10` otherwise.
- Default rules flag `failed_logins > 5`, `bytes_out > 500000`, and
  `admin_actions > 2`.
- An event is suspicious when any `|z| >= --z-threshold` or any rule fires.
  The reported score is the peak `|z|` plus triggered rule weights.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only; offline and deterministic.
