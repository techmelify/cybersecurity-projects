# 11 — Binary Analysis Tool (Python substitution)

**Upstream language: Rust. This implementation is a Python substitution** using `struct` from the standard library. It performs the same header-level inspection — ELF class/machine/sections/segments or PE type/machine/sections — without a loader or native dependencies.

## Run

```powershell
python binary_analysis_tool.py sample.bin
python binary_analysis_tool.py sample.bin --json
```

Library usage is bytes-in, report-out:

```python
from binary_analysis_tool import analyze

report = analyze(data)
```

## Supported fields

- **ELF:** class (32/64), byte order, e_machine, section headers with names from `.shstrtab`, and program headers.
- **PE:** PE32 vs PE32+, COFF machine, entry point, and the section table.

Malformed or truncated headers raise `ValueError`; unknown machine codes are reported rather than guessed. Only bytes are inspected — nothing is mapped, loaded, or executed.

## Test

```powershell
python -m unittest discover -s tests -v
```

15 deterministic tests. All fixtures are synthetic byte strings assembled with `struct.pack` in the test file; no sample malware is included.

## Safety

Pure header parsing. There are no subprocess calls, no dynamic loading, and no network access.
