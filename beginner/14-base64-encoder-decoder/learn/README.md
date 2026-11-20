# Learn — base64

## Encoding, not encryption

Base64 maps 3 bytes to 4 ASCII characters using a 64-character alphabet. It is reversible by anyone and provides no confidentiality. Its purpose is safe transport of binary data through text-only channels.

## Padding and alphabets

Standard base64 uses `+` and `/` with `=` padding. URL-safe base64 substitutes `-` and `_` so values can appear in URLs without escaping. Decoders must normalise the alphabet before strict validation.

## Why validate

Python's default decoder ignores non-alphabet characters. That can hide corrupted or maliciously crafted input. `validate=True` makes bad input fail loudly.
