# 09 — Quantum Resistant Encryption

A tiny SHA-256-based Lamport one-time signature scheme for education.

> **WARNING: This is a TOY implementation. It is NOT production post-quantum cryptography. A private key has a strict one-time limit: signing two different messages with the same key can reveal enough secret material to undermine that key. Never use these keys for real data, identities, or credentials.**

## Scope

Kept in Python as specified, using only `hashlib`, `hmac`, `random`, and the rest of the standard library. No external crypto library, network call, or cryptosystem integration is used. The seeded PRNG exists to make tests reproducible; it is not a cryptographically secure random source.

## Run

```powershell
python lamport_ots.py keygen --seed 7 --private-out private.json --public-out public.json
python lamport_ots.py sign --private private.json --message "measured once" --output signature.json
python lamport_ots.py verify --public public.json --message "measured once" --signature signature.json
python lamport_ots.py reuse-demo --seed 7 --message-a alpha --message-b beta
```

`keygen` and `reuse-demo` require a seed so demonstrations are deterministic. In any real design the seed would have to remain secret and come from a CSPRNG — which is one reason this toy must not be deployed.

## Test

```powershell
python -m unittest discover -s tests
```

17 tests. Standard library only; all keys and messages are generated from fixed seeds.

## Limitations

- One key = one message. The CLI does not enforce persistent state; the caller must never reuse a key.
- No checksum, key derivation hierarchy, key rotation, or multi-signature support.
- SHA-256 itself is not the weak point here; the construction, randomness, and one-time discipline are what make this unsuitable for production.
- Real post-quantum signatures need reviewed standards such as SLH-DSA/SPHINCS+ and vetted implementations.
