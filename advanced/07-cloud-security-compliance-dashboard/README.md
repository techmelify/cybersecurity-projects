# 07 — Cloud Security Compliance Dashboard

Offline rule-based audit of a synthetic cloud configuration snapshot.

## Substitution

The upstream Go/React dashboard is replaced by a Python standard-library CLI. There are no cloud SDKs, API calls, credentials, or network requests; the React view becomes a deterministic text or JSON report.

## Checks

- `CLOUD-S3-001` — public S3 buckets (public read/write flags, public ACLs, disabled access block)
- `CLOUD-IAM-001` — over-permissive Allow statements (wildcard actions on wildcard resources, or wildcard actions for wildcard principals)
- `CLOUD-EBS-001` — volumes that do not explicitly declare encryption at rest
- `CLOUD-LOG-001..003` — missing CloudTrail, VPC flow, or S3 access logging

## Snapshot shape

```json
{
  "buckets": [
    {"name": "private-logs", "public_read": false, "public_write": false,
     "public_access_block": true, "acl": "private"}
  ],
  "iam_policies": [
    {"name": "readonly", "statements": [
      {"effect": "Allow", "principal": "role/reader",
       "actions": ["s3:GetObject"], "resources": ["arn:example:bucket/*"]}
    ]}
  ],
  "volumes": [{"id": "vol-1", "encrypted": true}],
  "logging": {
    "cloudtrail_enabled": true,
    "vpc_flow_logs_enabled": true,
    "s3_access_logging_enabled": true
  }
}
```

## Run

```powershell
python compliance_dashboard.py snapshot.json
python compliance_dashboard.py snapshot.json --json
python compliance_dashboard.py snapshot.json --fail-on high
```

`--fail-on` exits 1 when a finding of that severity or higher exists; `none` (the default) only reports.

## Test

```powershell
python -m unittest discover -s tests
```

16 tests. Standard library only.

## Limitations

This is a teaching dashboard over caller-supplied synthetic data. It is not a CSPM product, does not validate real cloud accounts, and cannot prove that a resource is exploitable.
