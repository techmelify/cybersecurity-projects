# 16 — Hardware Security Module Emulator (Python substitution)

The upstream project is specified in Zig. It is reimplemented here as a **software HSM simulator** in Python: keys are derived from a synthetic master key, wrapped with AES-GCM, and used for HMAC-SHA-256 signing. Plaintext key bytes never leave the `HSM` object.

## API

```python
from hsm_emulator import HSM

hsm = HSM()
wrapped = hsm.generate_key("lab-key-1")     # no plaintext returned
signature = hsm.sign("lab-key-1", b"hello")  # HMAC-SHA-256
assert hsm.verify("lab-key-1", b"hello", signature)
```

`restore_key(wrapped)` unwraps into a fresh emulator and returns only the key id. `list_key_ids()`, `fingerprint()`, and `master_fingerprint()` expose one-way identifiers, not key material.

## CLI

```powershell
python hsm_emulator.py generate --key-id lab-key-1 --out wrapped.json
python hsm_emulator.py sign --wrapped wrapped.json --message "hello"
python hsm_emulator.py verify --wrapped wrapped.json --message "hello" --signature <hex>
```

Wrappers and signatures are JSON with hex-encoded byte fields.

## Scope and substitutions

- Zig → Python substitution is explicit. No hardware, device driver, PKCS#11 provider, network, or real credential is used.
- The default master key is a fixed **synthetic lab constant**. Supply your own 32-byte key only for further lab experiments; never reuse it for real data.
- AES-GCM comes from the installed `cryptography` package (permitted for this project). HMAC and hashing use the standard library. Deterministic key derivation and nonces keep tests reproducible; production systems should use a true random source and a real HSM.
- No key export command exists. A wrapper contains only nonce, ciphertext, and tag.

## Test

```powershell
python -m unittest discover -s tests -v
```

10 tests, offline and deterministic.

## Limitations

This is an emulator for learning key-wrapping and signing workflows. It offers no tamper resistance, secure element, role model, or audit logging. Do not treat it as a security boundary.
