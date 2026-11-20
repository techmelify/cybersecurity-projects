# 02 — Keylogger (educational event recorder)

A deliberately non-stealthy key-event recorder that demonstrates event handling, timestamps, and JSON Lines output.

## Safety boundary

- **No global keyboard hook.** The demo source reads stdin only.
- **No persistence, no hiding, no network, no exfiltration.**
- The CLI refuses to start without `--i-understand`.
- Use only on your own machine, with informed consent of anyone involved.

## Run

```powershell
python keylogger.py --i-understand -o keys.jsonl
```

Type normally, then press Ctrl+C. The `run()` function also accepts any iterable of strings, which is how the tests inject synthetic events without capturing real keystrokes.

## Test

```powershell
python -m unittest discover -s tests -v
```

7 tests, standard library only.

## Why this design

A real global hook would make the tests non-deterministic and turn the repository into dual-use tooling with no educational benefit. Separating the recorder from the event source keeps the concept intact while making it safe to run in CI.
