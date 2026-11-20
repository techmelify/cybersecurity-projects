# Learn — toy Lamport signatures

## Hash-then-reveal

The message is hashed to 256 bits. For each bit position the private key holds two secrets: one for 0 and one for 1. Signing reveals the secret chosen by that bit; verification hashes each revealed secret and compares it with the public key image for the expected bit.

## Why one-time

If the same key signs two different messages, the two messages differ at some bit positions. At each differing position the signer reveals the 0-secret in one signature and the 1-secret in the other. `leaked_secret_indexes` demonstrates exactly that. An attacker can then mix revealed secrets to forge signatures for other messages.

## Seeded randomness in this project

`random.Random(seed)` makes tests and demos repeatable. That is the opposite of what a real signature scheme needs: real keys require a cryptographically secure generator and strict secret handling. The seed here must be treated as part of the toy private key.

## Post-quantum context

Hash-based signatures rely on hash-function security, which is why they are studied for post-quantum use. This does not make a 256-line teaching toy production-ready. Parameter choices, randomness, state management, standardisation, and implementation review all matter.

## Exercises

- Implement a serial-number field to make key reuse visible in the signature format.
- Add a checksum over message bits, as WOTS schemes do, and discuss what it does and does not fix.
- Write a test that constructs a mixed-secret forgery after two signatures.
