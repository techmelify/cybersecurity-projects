import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chaos_engineering_security_tool import (  # noqa: E402
    SimulationConfig,
    build_plan,
    load_manifest,
    main,
    simulate,
)

YAML_MANIFEST = """
# security chaos plan (synthetic)
version: 1
scenarios:
  - id: tls-regression
    target: staging-api
    fault: tls_config_regression
    duration_seconds: 90
    blast_radius:
      services: [gateway, auth]
      users: 40 # synthetic users
      regions: [eu-west]
      data_sensitivity: high
    rollback:
      - restore_config
      - restart_gateway
"""

INLINE_MANIFEST = """
scenarios:
  - {id: quick-check, target: staging-api, fault: logging_drop}
"""


def manifest(fault="auth_delay", sensitivity="medium", users=250, enabled=True, rollback=None):
    return {
        "scenarios": [
            {
                "id": "s1",
                "title": "Auth delay drill",
                "target": "staging-api",
                "fault": fault,
                "duration_seconds": 120,
                "blast_radius": {
                    "services": ["gateway", "auth"],
                    "users": users,
                    "regions": ["us-east"],
                    "data_sensitivity": sensitivity,
                },
                "rollback": list(rollback) if rollback is not None else ["restore_config", "restart_gateway"],
                "enabled": enabled,
            }
        ]
    }


class ChaosEngineeringSecurityToolTests(unittest.TestCase):
    def test_load_json_manifest(self):
        document = load_manifest(json.dumps(manifest()))
        self.assertEqual(document["scenarios"][0]["fault"], "auth_delay")

    def test_load_yaml_like_manifest(self):
        document = load_manifest(YAML_MANIFEST)
        scenario = document["scenarios"][0]
        self.assertEqual(scenario["id"], "tls-regression")
        self.assertEqual(scenario["blast_radius"]["services"], ["gateway", "auth"])
        self.assertEqual(scenario["blast_radius"]["regions"], ["eu-west"])
        self.assertEqual(scenario["rollback"], ["restore_config", "restart_gateway"])

    def test_comments_and_scalar_types(self):
        document = load_manifest('version: 1\nenabled: false\nlabel: "value # kept"\n')
        self.assertEqual(document["version"], 1)
        self.assertIs(document["enabled"], False)
        self.assertEqual(document["label"], "value # kept")

    def test_inline_mapping_in_yaml(self):
        document = load_manifest(INLINE_MANIFEST)
        self.assertEqual(document["scenarios"][0]["id"], "quick-check")
        self.assertEqual(document["scenarios"][0]["fault"], "logging_drop")

    def test_build_plan_fields(self):
        scenario = build_plan(manifest())[0]
        self.assertEqual(scenario.id, "s1")
        self.assertEqual(scenario.title, "Auth delay drill")
        self.assertEqual(scenario.blast_radius.services, ("gateway", "auth"))
        self.assertEqual(scenario.blast_radius.users, 250)
        self.assertEqual(scenario.rollback, ("restore_config", "restart_gateway"))
        self.assertTrue(scenario.enabled)

    def test_unknown_fault_rejected(self):
        with self.assertRaises(ValueError):
            build_plan(manifest(fault="delete_all_data"))

    def test_unsupported_sensitivity_rejected(self):
        with self.assertRaises(ValueError):
            build_plan(manifest(sensitivity="catastrophic"))

    def test_duplicate_or_missing_id_rejected(self):
        with self.assertRaises(ValueError):
            build_plan({"scenarios": [{}, {}]})
        document = manifest()
        document["scenarios"].append(dict(document["scenarios"][0]))
        with self.assertRaises(ValueError):
            build_plan(document)

    def test_simulation_events(self):
        report = simulate(build_plan(manifest()))
        self.assertEqual({event.phase for event in report.events}, {"plan", "simulate", "verify", "rollback"})
        simulate_event = next(e for e in report.events if e.phase == "simulate")
        self.assertIn("no disruption was executed", simulate_event.message)

    def test_rollback_plan(self):
        report = simulate(build_plan(manifest()))
        self.assertEqual(
            report.rollback_plan,
            ("s1: restore_config", "s1: restart_gateway"),
        )

    def test_risk_increases_with_sensitivity(self):
        low = simulate(build_plan(manifest(sensitivity="low")))
        high = simulate(build_plan(manifest(sensitivity="high")))
        self.assertGreater(high.max_risk, low.max_risk)

    def test_disabled_scenario_is_skipped(self):
        report = simulate(build_plan(manifest(enabled=False)))
        self.assertEqual(report.risk_scores, {})
        self.assertEqual(report.rollback_plan, ())
        self.assertIn("skipped", report.events[0].message)

    def test_risk_budget_warnings(self):
        report = simulate(build_plan(manifest()), SimulationConfig(max_risk_score=10))
        self.assertEqual(len(report.warnings), 1)
        self.assertIn("s1", report.warnings[0])

    def test_verification_can_be_disabled(self):
        report = simulate(build_plan(manifest()), SimulationConfig(include_verification=False))
        self.assertNotIn("verify", {event.phase for event in report.events})

    def test_missing_rollback_warning(self):
        report = simulate(build_plan(manifest(rollback=[])))
        self.assertTrue(any("no rollback" in event.message for event in report.events))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.yaml"
            path.write_text(YAML_MANIFEST, encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["risk_scores"]["tls-regression"], 69)
            self.assertEqual(len(payload["rollback_plan"]), 2)

    def test_cli_over_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan.json"
            path.write_text(json.dumps(manifest()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(path), "--max-risk", "10"])
            self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
