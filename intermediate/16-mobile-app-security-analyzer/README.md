# 16 — Mobile App Security Analyzer (Python)

Python-only project. It analyzes a synthetic Android/iOS manifest JSON for excessive permissions, cleartext traffic, exported components, and missing secure flags. No APK/IPA parsing, device access, or network activity is involved.

## Run

```powershell
python mobile_analyzer.py manifest.json
```

Snapshot format:

```json
{
  "platform": "android",
  "package": "com.example.demo",
  "permissions": ["INTERNET", "READ_SMS", "ACCESS_FINE_LOCATION"],
  "cleartext_traffic": true,
  "components": [
    {"name": "ExportActivity", "kind": "activity", "exported": true},
    {"name": "InternalService", "kind": "service", "exported": false}
  ],
  "secure_flags": {
    "allowBackup": false,
    "debuggable": false,
    "cleartextTrafficPermitted": false
  }
}
```

## Checks

| Category | Severity | Trigger |
| --- | --- | --- |
| `excessive-permission` | high | A dangerous permission such as `READ_SMS` or `ACCESS_FINE_LOCATION` is requested. |
| `cleartext-traffic` | high | `cleartext_traffic` is true. |
| `exported-component` | high | A component is exported without a permission guard. |
| `missing-secure-flag` | medium | A secure flag is absent or set to an insecure value. |

## Test

```powershell
python -m unittest discover -s tests -v
```

Standard library only. All package names and component names in fixtures are synthetic.
