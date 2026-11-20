# 03 — Caesar Cipher

CLI encryption/decryption tool with brute-force and English-frequency scoring.

## Run

```powershell
python caesar.py encode "Attack at dawn" -s 3
python caesar.py decode "Dwwdfn dw gdzq" -s 3
python caesar.py crack "Dwwdfn dw gdzq" -n 5
```

## Test

```powershell
python -m unittest discover -s tests -v
```

12 tests, standard library only.
