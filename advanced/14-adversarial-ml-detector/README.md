# 14 — Adversarial ML Detector (defensive substitution)

The upstream catalogue lists an **Adversarial ML Attacker** synopsis. That offensive tool is replaced here with a *defensive* detector: it reads synthetic feature vectors and flags patterns associated with adversarial perturbation and distribution drift. There is no model, no TensorFlow, no gradient access, and no attack generation.

## Signals

| Signal | Rule |
| --- | --- |
| `z-score-outlier` | A feature is more than 3 standard deviations from the clean baseline mean. |
| `out-of-range-feature` | A feature lies outside the baseline min/max with a small tolerance. |
| `saturated-features` | Three or more features are pinned to 0 or 1 when the baseline rarely saturates. |
| `coordinated-small-perturbation` | Every feature shifts by a tiny amount (≤ 0.15) in the same direction. |
| `distribution-drift` | A batch mean shifts by more than 3 standard errors from the baseline. |

Scores combine into `benign` (< 3), `suspicious` (3–5), or `likely-adversarial` (≥ 6).

## Run

```powershell
python adversarial_detector.py --baseline baseline.json --input batch.json
python adversarial_detector.py --baseline baseline.json --input batch.json --z-threshold 2.5
```

Both JSON files are lists of records like `{"id": "sample-1", "values": [0.1, 0.2, 0.3]}`. `identifier`/`features` are also accepted.

## Scope and substitutions

- Original Python implementation; no third-party packages, network, or model calls.
- Vectors are synthetic and generated in code or supplied as local JSON. Statistics use `statistics.fmean`/`pstdev`, so results are deterministic.
- The defensive substitution is intentional: this project detects suspicious inputs rather than crafting them.

## Test

```powershell
python -m unittest discover -s tests -v
```

10 tests, standard library only.

## Limitations

These are transparent heuristics, not a trained classifier. A determined attacker can stay inside the rules; use the output as a triage signal alongside proper monitoring and access control.
