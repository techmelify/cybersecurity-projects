import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lab_planner import (  # noqa: E402
    Plan,
    build_plan,
    load_scope,
    main,
)

SCOPE_DATA = {
    "assets": [
        {"name": "lab-web-01", "network": "10.10.0.0/24", "owner": "blue-team", "environment": "lab"},
        {"name": "staging-api", "network": "10.20.0.0/24", "owner": "blue-team", "environment": "staging"},
        {"name": "prod-db", "network": "10.30.0.0/24", "owner": "ops", "environment": "production"},
    ],
    "tests": [
        {"id": "T01", "title": "Service inventory", "category": "recon", "asset": "lab-web-01"},
        {"id": "T02", "title": "Config baseline", "category": "configuration-review", "asset": "staging-api"},
        {"id": "T03", "title": "Safe scan", "category": "vulnerability-scan", "asset": "lab-web-01"},
        {"id": "T04", "title": "Production port check", "category": "recon", "asset": "prod-db"},
    ],
}


class LabPlannerTests(unittest.TestCase):
    def test_load_scope_parses_and_validates(self):
        scope = load_scope(SCOPE_DATA)
        self.assertEqual(len(scope.assets), 3)
        self.assertEqual(len(scope.tests), 4)
        with self.assertRaises(ValueError):
            load_scope({"assets": [{"name": "a"}, {"name": "a"}], "tests": []})
        with self.assertRaises(ValueError):
            load_scope({"assets": [], "tests": [{"id": "T", "title": "x", "category": "recon"}]})
        with self.assertRaises(ValueError):
            load_scope({"assets": "bad", "tests": []})

    def test_valid_plan_orders_steps_and_checklists(self):
        plan = build_plan(load_scope(SCOPE_DATA))
        self.assertIsInstance(plan, Plan)
        self.assertEqual([step.test_id for step in plan.steps], ["T01", "T02", "T03"])
        self.assertEqual([step.order for step in plan.steps], [1, 2, 3])
        self.assertIn("Confirm written authorisation", plan.steps[0].checklist[0])
        self.assertEqual(len(plan.refusals), 1)
        self.assertEqual(plan.refusals[0].target, "T04")
        self.assertIn("production", plan.refusals[0].reason)

    def test_requested_tests_filter(self):
        plan = build_plan(load_scope(SCOPE_DATA), requested_tests=["T03"])
        self.assertEqual([step.test_id for step in plan.steps], ["T03"])
        self.assertEqual(plan.refusals, ())

    def test_target_filter(self):
        plan = build_plan(load_scope(SCOPE_DATA), targets=["staging-api"])
        self.assertEqual([step.test_id for step in plan.steps], ["T02"])
        self.assertEqual([item.target for item in plan.refusals], ["T04"])

    def test_out_of_scope_target_refused(self):
        plan = build_plan(load_scope(SCOPE_DATA), targets=["lab-web-01", "ghost-host"])
        self.assertEqual([step.test_id for step in plan.steps], ["T01", "T03"])
        self.assertEqual(len(plan.refusals), 2)
        ghost = next(item for item in plan.refusals if item.target == "ghost-host")
        self.assertIn("out-of-scope", ghost.reason)

    def test_production_target_refused(self):
        plan = build_plan(load_scope(SCOPE_DATA), targets=["prod-db"])
        self.assertEqual(plan.steps, ())
        self.assertEqual(plan.refusals[0].reason, "production target refused")

    def test_unknown_test_refused(self):
        plan = build_plan(load_scope(SCOPE_DATA), requested_tests=["T99"])
        self.assertEqual(plan.steps, ())
        self.assertEqual(plan.refusals[0].reason, "unknown or unauthorised test id")

    def test_no_execution_imports(self):
        source = (Path(__file__).resolve().parents[1] / "lab_planner.py").read_text(encoding="utf-8")
        forbidden = re.compile(
            r"^\s*(?:import|from)\s+(?:subprocess|socket|requests|urllib|http)\b",
            re.MULTILINE,
        )
        self.assertIsNone(forbidden.search(source))

    def test_empty_scope_and_rules(self):
        plan = build_plan(load_scope({"assets": [], "tests": []}))
        self.assertEqual(plan.steps, ())
        self.assertEqual(plan.refusals, ())
        self.assertEqual(len(plan.rules_of_engagement), 4)
        self.assertIn("Written authorisation", plan.rules_of_engagement[0])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(SCOPE_DATA), encoding="utf-8")

            def run(*args: str) -> dict[str, object]:
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    self.assertEqual(main(["--scope", str(path), *args]), 0)
                return json.loads(buffer.getvalue())

            payload = run()
            self.assertEqual(len(payload["steps"]), 3)
            self.assertEqual(len(payload["refusals"]), 1)
            validation = run("--validate-only", "--target", "prod-db")
            self.assertFalse(validation["valid"])
            self.assertEqual(validation["refusals"][0]["reason"], "production target refused")


if __name__ == "__main__":
    unittest.main()
