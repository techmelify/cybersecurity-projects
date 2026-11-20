# 04 — DNS Lookup CLI Tool

Query A, AAAA, PTR, and basic IANA WHOIS records.

## Run

```powershell
python dns_lookup.py a example.com
python dns_lookup.py aaaa example.com
python dns_lookup.py ptr 8.8.8.8
python dns_lookup.py whois example.com
```

## Test

```powershell
python -m unittest discover -s tests -v
```

8 tests. Tests use injected resolver functions; only the CLI performs real network calls.

## Notes

WHOIS uses a direct port-43 connection to `whois.iana.org`, not a third-party API. Results are raw text and may be an IANA referral rather than the full registration record.
