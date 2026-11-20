# Learn — classical substitution

## The cipher

A Caesar cipher shifts each letter by a fixed amount modulo 26. It has only 26 keys, so brute force is trivial. Its value is as a teaching example for modular arithmetic, character encoding, and frequency analysis.

## Frequency scoring

English text has a characteristic letter distribution (E ≈ 12.7%, Z ≈ 0.07%). Scoring each candidate shift by how closely its letters match that distribution usually identifies the right key for longer messages. Short strings are unreliable — a five-letter sample can rank the wrong shift first.

## Design notes

- Non-alphabetic characters pass through unchanged, preserving punctuation and spaces.
- Case is preserved independently.
- The same `shift_text` function handles encode and decode via a flag, avoiding duplicated logic.
