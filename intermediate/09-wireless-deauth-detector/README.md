# 09 — Wireless Deauth Detector (Python substitution)

**Upstream language: Rust. This implementation is a Python substitution** using only the standard library. Rust's ownership model is not needed for offline log parsing; the detector keeps the same outcome — flood alerts grouped by receiver and access point — in pure Python.

## Run

```powershell
python wireless_deauth_detector.py events.log
python wireless_deauth_detector.py events.log --json --receiver-threshold 8
```

## Expected log format

```text
2026-11-20T10:00:00Z deauth receiver=02:00:00:00:00:01 ap=02:00:00:00:00:99 reason=7 rssi=-55
2026-11-20T10:00:01Z disassoc receiver=02:00:00:00:00:02 ap=02:00:00:00:00:99 reason=4
```

`deauth` and `disassoc` are both accepted. Unrelated lines are ignored; malformed frame lines raise a `ValueError` so bad data is not silently treated as an attack.

## Detection

- **Receiver flood:** at least `receiver_threshold` frames (default 8) for one `(receiver, AP)` pair inside a sliding window (default 10 seconds). Severity rises to `critical` at twice the threshold.
- **AP flood:** at least `ap_threshold` frames (default 20) on one AP from at least 3 distinct receivers in the window.

Reason codes are decoded for analyst context. Alerts include the first/last timestamps and the observed frame kinds and reason codes.

## Test

```powershell
python -m unittest discover -s tests -v
```

13 deterministic tests using synthetic MAC addresses (locally administered `02:...` prefix).

## Safety

No radio hardware, monitor mode, packet injection, or live capture is used. The tool only parses text supplied by the caller.
