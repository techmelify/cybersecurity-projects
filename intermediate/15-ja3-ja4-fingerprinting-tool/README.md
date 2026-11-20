# 15 — JA3/JA4 TLS Fingerprinting Tool (Python substitution)

Rust upstream, replaced here with a standard-library Python implementation. It computes JA3-style hashes from synthetic ClientHello field lists. There is no live TLS capture, no socket, and no handshake.

## Run

```powershell
python fingerprint.py hellos.json
python fingerprint.py hellos.json --algo ja3
```

Snapshot format (a JSON list):

```json
[
  {
    "version": 771,
    "ciphers": [49199, 49195, 52392],
    "extensions": [0, 10, 23],
    "curves": [23, 24],
    "formats": [0]
  }
]
```

## Semantics

- **JA3:** joins `version`, and the `-`-joined cipher, extension, curve, and format lists with commas, then takes the MD5 hex digest. Order matters, exactly as in the JA3 specification.
- **JA4-like:** a simplified teaching variant. Lists are sorted and de-duplicated, the cipher count is prefixed, and the first 16 hex characters of SHA-256 are used. It is **not** wire-compatible with real JA4.
- MD5 is used only as the historical JA3 hash primitive; it is not used for any security decision here.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only. All values are synthetic integers, not observed traffic.
