# 09 — Deserialization Gadget Lab (Python substitution)

Upstream specifies Ruby; this build uses Python `pickle` to show the same class of risk: deserialization can execute code embedded in a stream.

## Run

```powershell
python gadget_lab.py payload > lab.bin
python gadget_lab.py check lab.bin
python gadget_lab.py check lab.bin --allow-main
```

The payload calls only `_benign_marker`, a harmless in-repo function. It performs no system commands and no network access.

## Test

```powershell
python -m unittest discover -s tests -v
```

5 tests.

## Safety

This is a teaching lab. The gadget is deliberately harmless and the CLI blocks unknown globals by default. Do not point `unsafe_loads` at data from outside this repository. The real-world lesson is to avoid pickle for untrusted input and use a data-only format such as JSON.
