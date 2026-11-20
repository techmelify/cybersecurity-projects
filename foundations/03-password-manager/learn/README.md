# Learn — password-based encryption

## Why a KDF is needed

A master password is low-entropy and unsuitable as an encryption key. A password-based key derivation function stretches it with salt and work factors. Argon2id is memory-hard, which makes GPU and ASIC attacks expensive.

## Why AES-GCM

Encryption alone does not detect tampering. AES-GCM is authenticated encryption: changing a single ciphertext byte makes decryption fail. The `WrongPassword` exception covers both a wrong master password and a modified vault — deliberately, so the tool does not reveal which one occurred.

## Why a new nonce per write

GCM nonce reuse with the same key is catastrophic. Every save generates a fresh 12-byte nonce from `os.urandom`, and the nonce is stored alongside the ciphertext.

## Atomic writes

The new document is written to a temporary file, then `os.replace` swaps it into place. A crash mid-write therefore leaves the previous vault intact.

## Exercises

- Add a vault format version migration path.
- Add `--json` output for `list`.
- Add a password-strength estimator for stored credentials.
