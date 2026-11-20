# 15 — Reverse-Engineering Platform (Python substitution)

The upstream project is specified in C. Only Python is used here, so the native binary tooling is replaced with a **read-only static inspector** for synthetic byte blobs. No sample executes, no debugger attaches, and no host process is touched.

## What it reports

- **Header** — ELF or PE recognition, magic bytes, architecture/bitness, and declared section entries.
- **Strings** — printable ASCII runs with their byte offsets (length and count are capped).
- **Imports** — known `kernel32.dll`, `libc.so`, `libcrypto.so`, etc., plus generic `.dll`/`.so`/`.dylib` names found in strings.
- **Entropy** — Shannon entropy of the bytes, rounded to three decimals; a crude packed/unpacked signal.

## Run

```powershell
python binary_inspector.py --file sample.bin
python binary_inspector.py --hex 7f454c4602010100000000000000000002003e00
python binary_inspector.py --file sample.bin --min-string-length 6
```

Output is JSON. `--file` and `--hex` are mutually exclusive.

## Scope and substitutions

- C → Python substitution is explicit: no compiler, linker, or native disassembler is required.
- Blobs are synthetic and supplied locally. This is a lab-style triage helper, not malware analysis of real samples and not a payload builder.
- Standard library only; no network or subprocess use.

## Test

```powershell
python -m unittest discover -s tests -v
```

10 tests, deterministic and offline.

## Limitations

Header parsing covers common ELF/PE fields, not every optional header or packed/obfuscated layout. Imports are inferred from string evidence rather than a full import-table walk. Treat the report as a starting point for manual review.
