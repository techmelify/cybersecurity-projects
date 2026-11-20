# 01 — Simple Port Scanner (Python substitution)

Upstream specifies C++; this build uses Python `asyncio` because no C++ compiler is available on the host. Behaviour and learning goals are preserved.

## Run

```powershell
python port_scanner.py 127.0.0.1 -p 1-1024
python port_scanner.py localhost -p 22,80,443 -c 50 -t 0.5
```

Only TCP connect scanning is implemented. No SYN scans, no OS fingerprinting, no raw sockets.

## Test

```powershell
python -m unittest discover -s tests -v
```

8 tests. The tests open a real listener on `127.0.0.1` on an ephemeral port — no external network is used.

## Safety

Scan only hosts you own or have explicit written permission to test. The default target is not set; the host is always a required argument.
