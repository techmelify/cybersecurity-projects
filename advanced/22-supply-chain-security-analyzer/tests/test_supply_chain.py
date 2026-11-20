import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supply_chain import (  # noqa: E402
    Analysis,
    Component,
    Policy,
    analyze,
    load_components,
    main,
    render,
)


def clean_component() -> Component:
    return Component(
        name="web-ui",
        version="1.2.3",
        publisher="Acme Security",
        license="MIT",
        hashes=(f"sha256:{'a' * 64}",),
        provenance="signed-build-attestation",
    )


class SupplyChainTests(unittest.TestCase):
    def test_clean_component_has_no_findings(self):
        analysis = analyze([clean_component()])
        self.assertIsInstance(analysis, Analysis)
        self.assertEqual(analysis.component_count, 1)
        self.assertEqual(analysis.findings, ())
        self.assertIn("No policy findings", render(analysis))

    def test_provenance_gap(self):
        component = Component("lib-a", provenance="")
        findings = analyze([component]).findings
        self.assertTrue(any(f.category == "provenance-gap" for f in findings))
        relaxed = analyze([component], Policy(require_provenance=False)).findings
        self.assertFalse([f for f in relaxed if f.category == "provenance-gap"])

    def test_weak_hash_algorithms(self):
        weak = Component("lib-b", "1.0", "Acme Security", "MIT", ("md5:" + "a" * 32, "sha1:" + "b" * 40), "attested")
        details = [f.detail for f in analyze([weak]).findings if f.category == "weak-integrity"]
        self.assertTrue(any("md5" in detail for detail in details))
        self.assertTrue(any("sha1" in detail for detail in details))

    def test_missing_and_malformed_hashes(self):
        missing = analyze([Component("lib-c", provenance="attested")]).findings
        self.assertTrue(any(f.detail == "no integrity hash recorded" for f in missing))
        malformed = Component("lib-d", provenance="attested", hashes=("sha256:xyz",))
        findings = analyze([malformed]).findings
        self.assertTrue(any(f.detail == "malformed sha256 digest" for f in findings))

    def test_unusual_publisher_and_policy_override(self):
        component = Component("lib-e", publisher="Random Person", provenance="attested")
        findings = analyze([component]).findings
        publisher_findings = [f for f in findings if f.category == "unusual-publisher"]
        self.assertEqual(len(publisher_findings), 1)
        self.assertEqual(publisher_findings[0].severity, "medium")
        overridden = analyze([component], Policy(trusted_publishers=frozenset({"Random Person"}))).findings
        self.assertFalse([f for f in overridden if f.category == "unusual-publisher"])
        anonymous = analyze([Component("lib-f", publisher="anonymous", provenance="attested")]).findings
        self.assertTrue(any(f.severity == "high" for f in anonymous if f.category == "unusual-publisher"))

    def test_license_risks(self):
        restricted = Component("lib-g", publisher="Acme Security", license="AGPL-3.0", provenance="attested")
        unknown = Component("lib-h", publisher="Acme Security", license="UNKNOWN", provenance="attested")
        findings = analyze([restricted, unknown]).findings
        risks = {f.component: f for f in findings if f.category == "license-risk"}
        self.assertEqual(risks["lib-g"].severity, "high")
        self.assertEqual(risks["lib-h"].severity, "medium")
        overridden = analyze([restricted], Policy(restricted_licenses=frozenset({"MIT"}))).findings
        self.assertFalse([f for f in overridden if f.category == "license-risk"])

    def test_findings_sorted_deterministically(self):
        bad = Component("zeta", provenance="none")
        findings = analyze([bad, clean_component()]).findings
        self.assertEqual(findings[0].category, "provenance-gap")
        self.assertEqual(findings, analyze([clean_component(), bad]).findings)
        ranks = {"high": 1, "medium": 2}
        values = [ranks[f.severity] for f in findings]
        self.assertEqual(values, sorted(values))

    def test_load_components_wrapper(self):
        data = {
            "components": [
                {
                    "name": "lib-i",
                    "version": "2.0",
                    "publisher": "npm Registry",
                    "license": "Apache-2.0",
                    "hashes": "sha512:" + "c" * 128,
                    "attestation": "signed",
                }
            ]
        }
        components = load_components(data)
        self.assertEqual(components[0].provenance, "signed")
        self.assertEqual(len(components[0].hashes), 1)
        self.assertEqual(analyze(components).findings, ())

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps([{"name": "lib-j"}]), encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(out.getvalue())
            self.assertTrue(any(item["category"] == "provenance-gap" for item in payload))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), "--allow-missing-provenance"]), 0)


if __name__ == "__main__":
    unittest.main()
