import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mobile_analyzer import (  # noqa: E402
    Component,
    Manifest,
    analyze,
    load_manifest,
    main,
)

SAFE_FLAGS = {
    "allowBackup": False,
    "debuggable": False,
    "cleartextTrafficPermitted": False,
}


def categories(findings):
    return [finding.category for finding in findings]


class MobileAnalyzerTests(unittest.TestCase):
    def test_clean_manifest_has_no_findings(self):
        manifest = Manifest(
            platform="android",
            package="com.example.clean",
            permissions=("INTERNET",),
            components=(Component("Main", "activity"),),
            secure_flags=SAFE_FLAGS,
        )
        self.assertEqual(analyze(manifest), [])

    def test_dangerous_permission_flagged(self):
        manifest = Manifest(
            "android", "com.example.app", ("READ_SMS", "INTERNET"), secure_flags=SAFE_FLAGS
        )
        findings = analyze(manifest)
        self.assertEqual(categories(findings), ["excessive-permission"])
        self.assertEqual(findings[0].severity, "high")

    def test_cleartext_traffic_flagged(self):
        manifest = Manifest("ios", "com.example.app", cleartext_traffic=True, secure_flags=SAFE_FLAGS)
        self.assertIn("cleartext-traffic", categories(analyze(manifest)))

    def test_exported_component_without_permission_flagged(self):
        manifest = Manifest(
            "android",
            "com.example.app",
            components=(Component("Admin", "activity", exported=True),),
            secure_flags=SAFE_FLAGS,
        )
        findings = analyze(manifest)
        self.assertIn("exported-component", categories(findings))

    def test_exported_component_with_permission_is_allowed(self):
        manifest = Manifest(
            "android",
            "com.example.app",
            components=(
                Component("Admin", "activity", exported=True, permission="SignatureOnly"),
            ),
            secure_flags=SAFE_FLAGS,
        )
        self.assertNotIn("exported-component", categories(analyze(manifest)))

    def test_missing_and_insecure_flags_flagged(self):
        manifest = Manifest(
            "android",
            "com.example.app",
            secure_flags={"allowBackup": True},
        )
        findings = [f for f in analyze(manifest) if f.category == "missing-secure-flag"]
        self.assertEqual(len(findings), 3)

    def test_load_manifest(self):
        data = {
            "platform": "android",
            "package": "com.example.app",
            "permissions": ["CAMERA"],
            "cleartext_traffic": True,
            "components": [{"name": "Svc", "kind": "service", "exported": True}],
            "secure_flags": SAFE_FLAGS,
        }
        manifest = load_manifest(data)
        self.assertEqual(manifest.permissions, ("CAMERA",))
        self.assertEqual(manifest.components, (Component("Svc", "service", True),))
        self.assertTrue(manifest.cleartext_traffic)

    def test_findings_are_deterministic(self):
        manifest = Manifest(
            "android",
            "com.example.app",
            permissions=("CAMERA", "READ_SMS"),
            cleartext_traffic=True,
            components=(Component("A", "activity", exported=True),),
            secure_flags={},
        )
        self.assertEqual(analyze(manifest), analyze(manifest))

    def test_cli(self):
        data = {
            "platform": "android",
            "package": "com.example.app",
            "permissions": ["READ_SMS"],
            "secure_flags": SAFE_FLAGS,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(main([str(path)]), 0)
            path.write_text("[]", encoding="utf-8")
            self.assertEqual(main([str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
