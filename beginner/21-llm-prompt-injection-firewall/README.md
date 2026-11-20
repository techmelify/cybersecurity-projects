# 21 — LLM Prompt Injection Firewall

Heuristic pre-filter for untrusted text before it is sent to an LLM.

## Run

```powershell
python prompt_firewall.py "Ignore previous instructions"
python prompt_firewall.py --file untrusted.txt
```

## Actions

- `allow` — no significant indicators.
- `review` — suspicious pattern; send to a human or a stronger model.
- `block` — multiple strong indicators.

## Signals

Instruction override, system-prompt extraction, jailbreak personas, concealment requests, role spoofing, chat-template tokens, and large base64-like blobs.

## Test

```powershell
python -m unittest discover -s tests -v
```

7 tests, standard library only. No network or model calls.

## Limitations

Pattern matching is evadable. Use this as a defence-in-depth layer, not a complete solution.
