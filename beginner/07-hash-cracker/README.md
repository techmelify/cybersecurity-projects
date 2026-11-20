# 07 — Hash Cracker

Educational cracking of unsalted digests you generated yourself. Dictionary and bounded brute-force modes.

## Run

```powershell
python hash_cracker.py 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -w words.txt
python hash_cracker.py <sha256> -b 4 --charset abc123
```

## Test

```powershell
python -m unittest discover -s tests -v
```

10 tests, standard library only.

## Safety

Use only on hashes you created in a lab. No rainbow tables, no network requests, no real credential stores, no bcrypt/Argon2 attacks. Brute force is explicitly bounded by maximum length.
