# 18 — Automated Penetration Testing Planner (defensive lab planner)

This is a **defensive lab planner**, not a penetration-testing executor. It reads a JSON scope of owned lab/staging assets and explicitly authorised tests, then emits an ordered plan with a checklist for each test. Out-of-scope targets, production assets, and unknown or unauthorised test ids are refused with a reason.

**No test is executed.** There is no command runner, scanner, exploit, payload, network call, or contact with any target.

## Scope document

```json
{
  "assets": [
    {"name": "lab-web-01", "network": "10.10.0.0/24", "owner": "blue-team", "environment": "lab"}
  ],
  "tests": [
    {"id": "T01", "title": "Service inventory", "category": "recon", "asset": "lab-web-01"}
  ]
}
```

An asset is refused when its `environment` is `production`/`prod`/`live`, or when its name contains `prod`, `production`, or `live`. Tests must reference a declared asset.

## Run

```powershell
python lab_planner.py --scope scope.json
python lab_planner.py --scope scope.json --test T01 --target lab-web-01
python lab_planner.py --scope scope.json --validate-only
```

Output is JSON with `steps` (ordered checklist items), `refusals`, and a fixed `rules_of_engagement` list. `--validate-only` reports validity, step count, and refusals.

## Checklist categories

`recon`, `configuration-review`, `vulnerability-scan`, and `credential-audit` each have a safe, read-only checklist. Any other category receives a generic authorisation/read-only/documentation checklist. Credential-audit steps explicitly require synthetic lab accounts.

## Scope and substitutions

- Original Python implementation; synopsis-only upstream project. Standard library only.
- Deterministic and offline: no live targets, real credentials, subprocess calls, sockets, or external tools.
- The inputs are synthetic scope documents; the output is a planning artefact only.

## Test

```powershell
python -m unittest discover -s tests -v
```

10 tests, deterministic and offline.

## Limitations

The planner cannot verify that authorisation is genuine or that an asset is truly owned; it only applies the rules encoded in the supplied scope. A plan is a starting point for human review, not permission to act.
