# 11 — Phishing Domain Detector & Quishing Scanner

Defensive-only reimplementation of the synopsis. The upstream goal of *generating* phishing domains is intentionally replaced with detection: this tool scores domains and QR payloads for lookalike indicators.

## Run

```powershell
python detector.py domain examp1e.com
python detector.py domain exаmple.com --brand acme
python detector.py qr "https://bit.ly/abc"
```

## Signals

- Unicode homoglyphs, punycode, and hyphen insertion (normalization changes the name).
- Edit distance ≤ 2 from a configured brand.
- Brand name embedded in a longer label.
- QR payloads using shorteners, punycode, raw IPs, plain HTTP, or credential-themed paths.

## Test

```powershell
python -m unittest discover -s tests -v
```

9 tests, standard library only.

## Safety

No lookalike domains, QR codes, or lure content are generated. The tool only classifies strings you supply. Detection is heuristic: a low score is not proof of safety.
