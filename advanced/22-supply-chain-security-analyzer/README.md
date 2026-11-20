# 22 — Supply Chain Security Analyzer (Go → Python substitution)

The upstream project is written in Go. This build is a **Python substitution** that analyzes a local SBOM/dependency snapshot for provenance gaps, weak integrity hashes, unusual publishers, and license risks. **It is fully offline: no network calls, no registry lookups, and no package installation.**

## Run

```powershell
python supply_chain.py snapshot.json
python supply_chain.py snapshot.json --json
python supply_chain.py snapshot.json --trusted-publisher "Internal Build" --allow-missing-provenance
```

`snapshot.json` can be a list or an object with a `components` key:

```json
{
  "components": [
    {
      "name": "web-ui",
      "version": "1.2.3",
      "publisher": "Acme Security",
      "license": "MIT",
      "hashes": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      "provenance": "signed-build-attestation"
    },
    {"name": "legacy-lib", "version": "0.9", "publisher": "unknown", "license": "AGPL-3.0", "hashes": ["md5:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}
  ]
}
```

`--trusted-publisher` and `--restricted-license` replace the built-in lists when supplied; `--allow-missing-provenance` disables that check. `--json` emits findings as JSON for further processing.

## Checks

- **provenance-gap** (high): no build attestation is recorded.
- **weak-integrity** (high): no hash, a weak algorithm (`md5`, `sha1`, `sha224`), an unknown algorithm, or a malformed digest.
- **unusual-publisher** (medium, high for `unknown`/`anonymous`): publisher is missing or outside the trusted allowlist.
- **license-risk** (medium for missing/unknown, high for restricted licenses such as AGPL-3.0 or SSPL-1.0).

Findings are sorted by severity, category, and component for stable reports.

## Substitution notes

The Go implementation is replaced by a pure Python policy checker over a static JSON snapshot. It does not resolve dependencies, contact package registries, or execute package code.

## Test

```powershell
python -m unittest discover -s tests
```

9 tests, standard library only.
