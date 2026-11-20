# Learn — recognising layered text obfuscation

## What the detector looks for

Obfuscation usually leaves textual fingerprints even when the decoded content is harmless:

1. **Encoding runs.** Long base64 or hex runs stand out from ordinary prose. Validating the run by decoding it with `validate=True` (and requiring a high printable-byte ratio) avoids flagging plain alphanumeric words.
2. **Escape sequences.** Scripts often represent bytes as `\xNN`, `\uNNNN`, `\n`, and friends. A single escape is normal; a dozen in a row is a signal. Doubled backslashes indicate a second escaping layer.
3. **XOR markers.** XOR is a transformation, not a payload. The detector looks for *descriptions of the transform* - `0x41 ^ 0x2a`, `xor_key`, `mask`, `decode` - rather than implementing one.
4. **Character-code building.** Repeated `chr()`/`ord()` calls suggest that a string is assembled one character at a time.
5. **Layering.** Two or more distinct encoding families is the strongest signal, so it gets a dedicated bonus.

## Why this is the safe direction

A generator would need the same primitives plus a way to emit an artefact. This project uses the primitives only for validation and throws away every decoded byte. That is the **safety substitution** required for this topic: study the detection side, never build the tool that would evade it.

## Design notes

- Indicator order is fixed by the check sequence, so results are reproducible.
- The score is capped at 100 so a pathological input cannot produce meaningless numbers.
- Reports never echo the matched text. A detector should not accidentally become a distribution channel for the content it finds.
- Thresholds are intentionally conservative. False positives are expected on fixture data; treat the score as a triage hint, not a verdict.
