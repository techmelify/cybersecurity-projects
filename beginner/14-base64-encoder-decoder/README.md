# 14 — Base64 Encoder/Decoder

Strict base64 codec for text and files, with standard and URL-safe alphabets.

## Run

```powershell
python base64_tool.py encode "hello world"
python base64_tool.py decode "aGVsbG8gd29ybGQ="
python base64_tool.py --urlsafe encode "hello"
python base64_tool.py encode --file input.bin
python base64_tool.py decode --file-in encoded.txt --file-out output.bin
```

## Test

```powershell
python -m unittest discover -s tests -v
```

6 tests, standard library only. Decoding uses `validate=True`, so stray characters are rejected instead of silently ignored.
