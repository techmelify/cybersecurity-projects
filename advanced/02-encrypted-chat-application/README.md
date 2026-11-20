# 02 — Encrypted Chat Application (Python local simulation)

Upstream specifies a FastAPI service with a SolidJS frontend. This build is a
**local simulation only**: no server, no browser, no network calls, and no
multi-user delivery. Messages are encrypted into one local JSON file.

- **Cipher:** AES-256-GCM with a fresh 12-byte nonce per message
- **Key:** a 32-byte shared *lab* key derived from a public phrase (or loaded
  from an optional local key file); never for real credentials or messages
- **AAD:** the message sequence number, so records cannot be silently reordered
- **Storage:** base64 nonce + ciphertext only; sender, body, and timestamp are
  encrypted inside the payload

## Run

```powershell
python chat.py init chat.json
python chat.py send chat.json alice "hello lab" --sequence 1 --timestamp "2026-01-01T00:00:00Z"
python chat.py send chat.json bob "ack" --sequence 2 --timestamp "2026-01-01T00:00:05Z"
python chat.py read chat.json

# Optional local key file (generated once, never printed).
python chat.py keygen lab.key
python chat.py init keyed.json --key-file lab.key
python chat.py read keyed.json --key-file lab.key
```

Timestamps and sequence numbers are supplied by the caller so runs are
deterministic; the tool does not read the wall clock.

## Test

```powershell
python -m unittest discover -s tests -v
```

Requires `cryptography` (verified with 50.0.2). Offline and deterministic.
Keys are excluded from object representations, stdout, and error messages.

## Limitations

This is a teaching simulation, not a secure messenger. The default lab key is
public by design, there is no forward secrecy, no identity authentication, no
key rotation, and no transport.
