<div align="center">
  <img src="assets/hero.svg" alt="Secrets Scanner banner" width="100%" />
</div>

<br />

<div align="center">

# 🔐 Secrets Scanner

![Tier](https://img.shields.io/badge/tier-INTERMEDIATE-C084FC?style=for-the-badge)
![Domain](https://img.shields.io/badge/domain-Secret%20Hygiene-4C1D95?style=for-the-badge)
![Language](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-13%20passing-16A34A?style=for-the-badge)
![Deps](https://img.shields.io/badge/deps-standard%20library-gray?style=for-the-badge)

> **Find it, mask it, never repeat it.** Shape checks first, entropy second — and every reported value is redacted before it reaches the screen.

</div>

---

## 🎯 What it does

`scan_snapshot()` takes a `path -> text` mapping and returns a `ScanResult` of masked findings. Specific regexes catch AWS-like access key IDs, PEM private key headers, and JWT-shaped tokens; a fallback checks long mixed-class tokens against a configurable Shannon entropy threshold. Overlapping candidates collapse in favour of the specific pattern. Lines carrying `nosec`, `pragma: allowlist secret`, or `secrets-scanner: ignore` are suppressed, and a `secrets-scanner: disable-file` marker in the first ten lines suppresses the whole file.

> **Scope & safety.** Upstream language: Go. This implementation is a Python substitution because only the Python standard library is available on the build host. It reproduces the intended behavior — regex and entropy detection over a text snapshot — without Go tooling. Findings are masked before printing so a report cannot leak the value it found. Read-only analysis. No path is discovered implicitly by the library, and no secret is sent anywhere. The 13 deterministic tests use synthetic strings; no real credentials or network access.

## 🧠 How it works

```mermaid
stateDiagram-v2
    [*] --> Candidate: regex or entropy match
    Candidate --> Suppressed: allowlist marker on line or file
    Candidate --> Masked: specific pattern wins overlaps
    Masked --> Reported: scan_snapshot collects findings
    Suppressed --> Counted: suppressed counter increments
    Reported --> [*]
    Counted --> [*]
```

Entropy alone produces false positives on hashes and base64 images, so the fallback also requires a minimum length (24) and both letters and digits. Suppression is an explicit, reviewable contract: line-level markers silence one line only, while file-level suppression is deliberately limited to a marker near the top.

## 🚀 Quick start

```powershell
python secrets_scanner.py config.yaml example.txt --json
python secrets_scanner.py example.txt
```

Library callers provide the snapshot directly:

```python
from secrets_scanner import scan_snapshot

result = scan_snapshot({'app.cfg': 'api_key = EXAMPLE'})
```

The sample file below was written to `%TEMP%` with Python. All values are synthetic shapes, not live credentials:

```text
aws_access_key_id = AKIAZZZZZZZZZZZZZZZZ
token = aB3dEf7gH9jK2mN4pQ6rS8tU0vW2xY4
jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlZm9ydGVzdGluZ3B1cnBvc2Vz
safe = public-value  # nosec
```

### Real output

```text
$ python secrets_scanner.py sample.txt
$env:TEMP\oc_sample.txt:1:21 aws_access_key (entropy=0.00) AKIA...ZZ
$env:TEMP\oc_sample.txt:2:9 high_entropy_token (entropy=4.83) aB3d...Y4
$env:TEMP\oc_sample.txt:3:7 jwt (entropy=0.00) eyJh...Vz
3 finding(s) in 1 file(s), 0 suppressed
```

The CLI exits with status 1 when findings exist, so it can gate a pipeline; status 0 means a clean snapshot.

## 📂 Project structure

```text
07-secrets-scanner/
├── assets/hero.svg            # generated visual identity
├── secrets_scanner.py         # patterns + entropy + snapshot API + CLI
├── learn/README.md            # shape-first detection and suppression
└── tests/test_secrets_scanner.py # 13 deterministic tests
```

## 🔍 Why it matters

- **Reports must not re-leak.** Masking means pasting a scan result into a ticket is safe.
- **Shape beats guesswork.** Vendor-like prefixes give high-confidence, well-labelled hits; entropy is only the fallback.
- **Snapshots keep I/O at the edge.** Accepting a mapping makes the core a pure function and the tests deterministic.

## 🧪 Tests

```powershell
python -m unittest discover -s tests -v
```

13 deterministic tests covering the entropy helper, each pattern, low-entropy rejection, line and file suppression, custom markers, duplicate collapse, snapshot path/line reporting, and CLI output. Synthetic strings only; no real credentials or network access.

## 📚 Learn more

Read [the concept notes](learn/README.md) for shape-first detection, why entropy needs guards, snapshot-based design, suppression as a contract, and a few suggested exercises.

---

<div align="center">
  <sub>Part of <b>cybersecurity-projects</b> · Intermediate tier · Built from a synopsis, original implementation.</sub>
</div>
