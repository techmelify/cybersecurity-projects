# 03 — Password Manager

Encrypted local vault unlocked by a master password.

- **KDF:** Argon2id (32 MiB, 3 iterations, 4 lanes) with a fresh 16-byte salt
- **Cipher:** AES-256-GCM with a fresh 12-byte nonce per write and a fixed AAD
- **Storage:** one JSON file containing salt, nonce, and ciphertext only

## Run

```powershell
python vault.py vault.json init
python vault.py vault.json add mail alice 'S3cret!'
python vault.py vault.json list
python vault.py vault.json get mail alice
python vault.py vault.json delete mail alice
```

The master password is prompted for with `getpass` and is never stored or logged.

## Test

```powershell
python -m unittest discover -s tests -v
```

12 tests. Requires `cryptography>=45` for `Argon2id`; verified with 50.0.2.

## Limitations

This is a learning implementation, not a production password manager. It has no recovery flow, no hardware-key support, no secure memory wiping, and no multi-user sharing. Do not store real credentials in it.
