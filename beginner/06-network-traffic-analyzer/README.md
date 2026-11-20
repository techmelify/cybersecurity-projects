# 06 — Network Traffic Analyzer (Python substitution)

Upstream provides C++ and Python variants; this is a pure-Python offline PCAP parser. No live capture, no admin rights, no dependencies.

## Run

```powershell
python pcap_analyzer.py capture.pcap
python pcap_analyzer.py capture.pcap --json --top 10
```

Supports classic little-endian libpcap files with Ethernet link type. Parses IPv4 TCP, UDP, and ICMP headers and reports protocol counts, top talkers, and top conversations.

## Test

```powershell
python -m unittest discover -s tests -v
```

6 tests. Tests synthesize pcap bytes in memory — no capture file or network access needed.

## Scope

No reassembly, no application-layer parsing, no IPv6, no pcapng. Those are deliberate omissions to keep the parser readable.
