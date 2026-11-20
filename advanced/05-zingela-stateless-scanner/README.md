# 05 — Zingela Stateless Scanner (Python substitution)

Upstream specifies Zig. This build replaces Zig with Python and is entirely
**stateless and offline**: it parses a saved nmap-like text report and matches
hosts, ports, and services against a local risk catalog. It never scans, opens
sockets, invokes nmap, or contacts a target.

## Run

```powershell
python stateless_scanner.py --demo
python stateless_scanner.py saved_scan.txt --min-severity high
python stateless_scanner.py saved_scan.txt --catalog catalog.json --json
```

Expected input shape:

```text
Nmap scan report for 192.0.2.10
Host is up.
PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 9.0
23/tcp  open   telnet   Linux telnetd
```

`Nmap scan report for name (address)` is also supported. Only `open` ports are
considered for risk matches. A catalog override is a JSON list of objects with
`service`, `severity`, `note`, and an optional `ports` list.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only; offline and deterministic.
