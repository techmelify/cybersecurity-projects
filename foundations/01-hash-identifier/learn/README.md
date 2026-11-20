# Learn — hash formats

## Why format identification matters

Before you can validate, store, or crack a hash, you need to know what you are looking at. A 32-character hex string might be an MD5 digest, an NTLM password hash, or an LM hash. Treating one as another produces silent failures.

## Signals used here

1. **Prefix** — salted formats self-describe: bcrypt starts `$2b$`, PHC strings start `$argon2id$`.
2. **Length** — unsalted digests have fixed encoded lengths (MD5 32, SHA-1 40, SHA-256 64, SHA-512 128 hex characters).
3. **Charset** — hex vs base64-ish vs PHC structure.

## Confidence is part of the answer

A detection without a confidence level invites over-trust. This project returns `high`, `medium`, or `low` with every candidate so callers can decide how much to rely on it.

## What this tool deliberately does not do

- No hash computation or comparison.
- No password cracking, wordlists, or rainbow tables.
- No parsing of password-manager vaults or system credential stores.

It only classifies text you give it.

## Exercises

- Add SHA-3 / Keccak length signatures (64/96/128 hex — note the ambiguity with SHA-2).
- Add a `--json` output mode for piping into other tools.
- Extend confidence to distinguish uppercase-only hex from mixed case.
