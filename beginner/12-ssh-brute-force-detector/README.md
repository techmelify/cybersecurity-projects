# 12 — SSH Brute Force Detector

Offline detector for repeated `Failed password` events followed by a possible compromise.

## Run

```powershell
python detector.py auth.log --threshold 5 --window 300
```

## Logic

- Parse standard syslog-style sshd lines.
- Group failures by source IP.
- Find the largest cluster inside the sliding time window.
- Alert when the cluster reaches the threshold and note a success within 10 minutes.

## Test

```powershell
python -m unittest discover -s tests -v
```

8 tests. Log lines are synthetic; no live auth log is read.

## Safety

This is a defensive log parser. It does not attempt logins, open sockets, or modify system state.
