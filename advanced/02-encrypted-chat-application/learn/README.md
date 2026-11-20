# Learn — authenticated encryption for stored messages

## AES-GCM in one paragraph

AES-GCM provides both confidentiality and integrity. Encryption hides the
plaintext; the authentication tag makes any modification detectable. A message
is decryptable only with the same key, nonce, and associated data used during
encryption.

## Why a fresh nonce per message

Reusing a (key, nonce) pair with GCM can leak information about plaintexts and
forgery tags. Each `append` call draws a new 12-byte nonce, which is stored in
clear next to the ciphertext because a nonce is not secret. Tests inject fixed
nonces only to make file comparisons deterministic.

## What AAD accomplishes

Associated authenticated data is authenticated but not encrypted. Binding the
sequence number as AAD means swapping two records fails decryption even if an
attacker keeps each record's bytes intact.

## Keeping keys out of logs

The store object's `repr` omits the key, `AuthError` has a fixed message, and
the CLI never prints key bytes. A `keygen` command writes hex to a file and
reports only the file path. The default lab key is derived from a published
phrase so it must never protect real data.

## Exercises

- Add key-file rotation that re-encrypts all records.
- Add an export that includes decrypted messages only after explicit confirmation.
- Add a record checksum separate from the GCM tag and compare failure modes.
