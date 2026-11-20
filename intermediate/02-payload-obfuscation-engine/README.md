# 02 — Payload Obfuscation Detector

**Safety substitution:** the upstream synopsis is an offensive *payload obfuscation engine*. This project is the defensive inverse: a detector that scores text for obfuscation indicators. It contains **no obfuscator, no encoder, no XOR routine, and no weaponized payload**. Base64/hex decoding is used only to validate that a candidate run is really encoded text; decoded bytes are counted and discarded, never printed or written.

> **Python substitution:** the upstream implementation language is replaced by a standard-library-only Python CLI. The learning goal shifts from producing obfuscated output to recognising its textual signatures in logs, emails, and scripts.

## Run

```powershell
python obfuscation_detector.py --text "mask = 0x41 ^ 0x2a"
python obfuscation_detector.py --file sample.txt --json
```

## Indicators

| Kind | Signal | Weight |
|---|---|---|
| `base64` | run of 20+ base64 chars that decodes to printable bytes | 20 |
| `hex` | run of 32+ hex chars that decodes to printable bytes | 20 |
| `hex_escapes` | 8 or more `\xNN` sequences | 15 |
| `unicode_escapes` | 6 or more `\uNNNN` sequences | 10 |
| `escaped_string` | 12 or more escape sequences of any supported kind | 15 |
| `double_escape` | 4 or more doubled-backslash runs | 10 |
| `xor_literal` | numeric XOR expression such as `0x41 ^ 0x2a` | 20 |
| `xor_keyword` | `xor`/`xor_key` near `key`, `decode`, or `mask` | 15 |
| `char_codes` | 3 or more `chr()`/`ord()` calls | 10 |
| `layered_encoding` | two or more distinct encoding layers | 15 |

The score is the sum of triggered weights, capped at 100. Levels: 0-19 `low`, 20-49 `medium`, 50-79 `high`, 80+ `critical`. `analyze_text(text)` is a pure function returning an immutable `Detection`. Reports show indicator kinds, offsets, and counts - never the obfuscated text itself.

## Test

```powershell
python -m unittest discover -s tests -v
```

21 tests, standard library only, no network calls. Every fixture is synthetic text generated inside the tests.

## Safety

This is an analysis tool for text you are authorised to inspect. It does not generate, execute, or transmit anything. A high score is a review hint, not proof of malice: legitimate build scripts and test data can trigger the same patterns.
