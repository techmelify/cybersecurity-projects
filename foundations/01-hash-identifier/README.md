# 01 — Hash Identifier

Identify hash formats by prefix, length, and character set. Pure static analysis — nothing is hashed, cracked, or sent anywhere.

## Run

```powershell
python hash_identifier.py d41d8cd98f00b204e9800998ecf8427e
python hash_identifier.py --file samples.txt
```

## Detect

| Format | Signal | Confidence |
|---|---|---|
| bcrypt | `$2a$` / `$2b$` / `$2y$` + 60 chars | high |
| Argon2, scrypt, PBKDF2 | PHC `$alg$v=N$...` string | high |
| SHA-1 / 224 / 256 / 384 / 512 | 40 / 56 / 64 / 96 / 128 hex chars | high |
| MD5 / NTLM / LM | 32 hex chars | medium — length alone is ambiguous |
| Malformed bcrypt | bcrypt prefix, wrong length | low |
| Unknown hex / text | no matching signature | low |

## Test

```powershell
python -m unittest discover -s tests -v
```

13 tests, no dependencies.

## Notes

Length and charset are weak signals: 32 hex characters could be MD5, NTLM, or LM. The tool reports all three rather than guessing, and labels the confidence accordingly. Full identification needs context (which application produced the value, salt format, etc.).

See `learn/README.md` for the concepts.
