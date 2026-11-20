# 17 — Network Covert Channel Detector (defensive substitution)

The upstream catalogue lists a **Network Covert Channel** synopsis in Rust. This project deliberately replaces it with a **detector**, not a sender. It reads synthetic packet timing/size logs and scores how much they resemble known covert-channel patterns. There is no encoder, transmitter, socket, capture, or live target.

## Signals

| Signal | Rule | Score |
| --- | --- | --- |
| `regular-timing` | At least five gaps with mean absolute deviation / mean gap ≤ 0.05 (or ≤ 0.15 for a weaker hit). | 3 / 2 |
| `size-encoding` | Eight or more packets using 2–6 recurring sizes with size entropy ≤ 1.6 bits. | 2 |
| `low-rate-bursts` | Three or more tight clusters (≤ 0.5 s inside) separated by ≥ 5 s quiet gaps. | 2 |

Total score maps to `benign` (< 2), `suspicious` (2–4), or `likely-covert` (≥ 5). Signals are sorted by name so output is stable.

## Run

```powershell
python covert_channel_detector.py --demo
python covert_channel_detector.py --file events.json
```

`events.json` is a list of `{"timestamp": 0.0, "size": 512}` records. `t` and `bytes` are accepted as aliases. Optional `source` and `destination` fields are copied into the assessment input but do not affect scoring.

## Scope and substitutions

- Rust → Python and offensive → defensive substitutions are both explicit.
- Only synthetic logs are used. No packet is generated on a network and no covert channel is implemented.
- Standard library only; all functions are pure and deterministic.

## Test

```powershell
python -m unittest discover -s tests -v
```

10 tests, offline.

## Limitations

Legitimate traffic can be regular or bursty (heartbeats, batch jobs), so scores are triage hints, not proof. Correlate with endpoint context before acting.
