# 05 — Supply-Chain Graph Risk Analyzer

A defensive analyzer for a synthetic dependency graph.

**Safety substitution:** the upstream synopsis is a supply-chain *attack simulator*. This project only analyses a local JSON description of packages and relationships. It flags risk signals; it does **not** create malicious packages, download dependencies, build artefacts, publish to a registry, or execute package code.

> **Python substitution:** the upstream implementation is replaced by a standard-library-only Python CLI. All packages, maintainers, and names in the tests are synthetic strings, so nothing can be installed or harmed.

## Run

```powershell
python dependency_analyzer.py --graph graph.json
python dependency_analyzer.py --graph graph.json --json --stale-days 180
```

Graph file format:

```json
{
  "packages": [
    {"name": "app", "version": "1.2.0", "maintainers": ["alice"], "last_release_days": 20}
  ],
  "dependencies": [
    {"source": "app", "target": "app", "kind": "runtime"}
  ],
  "known_names": ["requests"],
  "trusted_maintainers": ["alice"]
}
```

## Rules

| Rule | Trigger | Severity |
|---|---|---|
| `typosquat_like` | package name is one edit from, or highly similar to, a known name | high |
| `unmaintained` | `last_release_days` reaches `--stale-days` (default 365) | medium |
| `unexpected_maintainer` | a maintainer is outside the trusted list, when a list is supplied | high |
| `unknown_maintainer` | no maintainers listed, when a trusted list is supplied | low |
| `unknown_dependency` | a dependency points at a package not in the graph | medium |

Similarity uses Levenshtein distance plus `difflib.SequenceMatcher`. The score sums severity points (high 20, medium 10, low 5) capped at 100. Risks and counts are sorted, so output is deterministic.

## Test

```powershell
python -m unittest discover -s tests -v
```

24 tests, standard library only, no network calls. Every graph fixture is synthetic.

## Safety

Name similarity and staleness are weak signals: a legitimate package can look similar to a popular one, and quiet maintenance does not prove compromise. Treat findings as prompts for human review.
