# 21 — Subdomain Takeover Scanner (defensive DNS snapshot analyzer, Go → Python substitution)

Upstream is Go and the synopsis is offensive. This build is a **defensive
substitution in Python**: it analyzes CNAME records that you supply in a JSON
snapshot. It performs **no live DNS queries**, opens no sockets, and never
attempts to claim a resource.

## Run

```powershell
python dns_snapshot_analyzer.py snapshot.json
python dns_snapshot_analyzer.py snapshot.json --json
```

Snapshot (all names are synthetic):

```json
{
  "cname_records": [
    {"host": "blog.example.test", "target": "demo-user.pages.test."},
    {"host": "old.example.test", "target": "unclaimed.hosting.test"}
  ],
  "known_services": [
    {
      "provider": "Demo Pages",
      "domains": ["pages.test"],
      "note": "Check that the custom domain is still bound."
    }
  ],
  "dangling_targets": ["unclaimed.hosting.test"]
}
```

`dangling_targets` is an observation supplied by the snapshot; the tool does
not verify it over the network.

## Checks

- `DNS-001`: CNAME target explicitly marked dangling in the snapshot.
- `DNS-002`: CNAME target matches a known takeover-prone provider domain (longest suffix wins).
- `DNS-003`: CNAME points at a bare provider domain rather than a tenant-specific target.

## Test

```powershell
python -m unittest discover -s tests
```

7 deterministic tests. No network or live DNS resolution is used.
