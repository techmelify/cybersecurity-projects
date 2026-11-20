# 17 — DLP Scanner (Python)

Python-only project. It scans text snapshots for PII/secret-like patterns, assigns severity, and redacts each match. All test data is synthetic; no real personal data, credential store, or network service is used.

## Run

```powershell
python dlp_scanner.py snapshots.json
```

Snapshot format:

```json
{
  "note.txt": "Contact user@example.test or card 4111 1111 1111 1111."
}
```

## Patterns

| Kind | Severity | Detection |
| --- | --- | --- |
| `email` | low | Email-shaped address (`.test` fixtures). |
| `national-id-like` | high | Three-two-four digit group shape. |
| `credit-card-like` | high | 13-19 digit candidate that passes the Luhn checksum. |
| `api-key` | high | Synthetic AWS/GitHub/OpenAI-style key prefixes. |

## Output safety

A `Finding` holds the raw match for programmatic checks, but the CLI prints only the redacted form. Redaction keeps two leading and two trailing characters and masks the rest with `*`.

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only. Pattern matching is heuristic: a hit is a lead for review, not proof of a real secret.
