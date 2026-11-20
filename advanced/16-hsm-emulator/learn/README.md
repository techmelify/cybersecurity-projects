# Learn — key wrapping and HSM concepts

## What an HSM provides

A hardware security module performs cryptographic operations internally so keys never appear in application memory. This emulator keeps the same interface shape — generate, wrap, restore, sign, verify — while storing keys in a Python dictionary. It teaches the workflow, not the hardware guarantees.

## Wrapping with AES-GCM

AES-GCM is an authenticated encryption mode. It needs a nonce, a master key, and optional associated data. The output contains ciphertext and a 16-byte authentication tag; changing either makes decryption fail. Here the key id is associated data, so a wrapper cannot be relabelled as another key.

## Signing with HMAC

HMAC-SHA-256 combines a secret key with a message to produce a tag. Verification recomputes the tag and compares it in constant time with `hmac.compare_digest`, which reduces timing leaks.

## Why avoid plaintext export

Every export is another place a secret can leak. Returning only a wrapped blob, a one-way fingerprint, or a signature keeps the secret inside the trust boundary. A real HSM adds physical protections on top of the same principle.

## Lab caution

Deterministic derivation and fixed nonces exist solely for reproducible tests. Real systems must use random keys and unique nonces, and should rely on a certified device rather than a software emulator.
