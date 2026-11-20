# 19 — DNS Sinkhole (Python substitution)

Upstream specifies Go; this build is a Python hosts-file blocklist manager. No DNS server is started.

## Run

```powershell
python sinkhole.py hosts.txt blocklist.txt
python sinkhole.py hosts.txt blocklist.txt --apply
python sinkhole.py hosts.txt blocklist.txt --ip 127.0.0.1 --apply
```

Without `--apply`, the merged file is printed as a dry run.

## Behaviour

- Reads a plain list of domains (inline comments allowed).
- Maintains one marked block delimited by `BEGIN` / `END` comments.
- Re-running replaces the old block instead of appending duplicates.
- Writes atomically-safe text (in-place write, no partial config generation).

## Test

```powershell
python -m unittest discover -s tests -v
```

6 tests. Tests use temporary files; no real hosts file is touched.
