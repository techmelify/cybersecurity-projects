import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dependency_analyzer import (  # noqa: E402
    Dependency,
    Graph,
    Package,
    analyze_graph,
    edit_distance,
    format_analysis,
    load_graph,
    main,
    typosquat_candidates,
)

TRUSTED = ("alice",)


def graph(packages=(), dependencies=(), known=(), trusted=TRUSTED):
    return Graph(tuple(packages), tuple(dependencies), tuple(known), tuple(trusted))


def rules(analysis):
    return {risk.rule for risk in analysis.risks}


class SimilarityTests(unittest.TestCase):
    def test_edit_distance(self):
        self.assertEqual(edit_distance("requests", "reqests"), 1)
        self.assertEqual(edit_distance("requests", "requests"), 0)
        self.assertEqual(edit_distance("cat", "dog"), 3)
        self.assertEqual(edit_distance("", "abc"), 3)

    def test_typosquat_one_edit(self):
        self.assertEqual(typosquat_candidates("reqests", ["requests"]), ("requests",))

    def test_typosquat_transposition(self):
        self.assertEqual(typosquat_candidates("reqeusts", ["requests"]), ("requests",))

    def test_typosquat_results_are_sorted(self):
        found = typosquat_candidates("reqests", ["requests", "reqwest"])
        self.assertEqual(found, tuple(sorted(found)))

    def test_exact_name_is_not_a_candidate(self):
        self.assertEqual(typosquat_candidates("requests", ["requests"]), ())

    def test_short_names_are_skipped(self):
        self.assertEqual(typosquat_candidates("abc", ["abd"]), ())

    def test_unrelated_name_is_not_a_candidate(self):
        self.assertEqual(typosquat_candidates("flask-app", ["requests"]), ())


class AnalyzeGraphTests(unittest.TestCase):
    def test_clean_graph(self):
        result = analyze_graph(graph(
            packages=[Package("flask-app", maintainers=("alice",), last_release_days=10)],
            dependencies=[Dependency("flask-app", "flask-app")],
            known=["requests"],
        ))
        self.assertEqual(result.risks, ())
        self.assertEqual(result.score, 0)

    def test_typosquat_risk(self):
        result = analyze_graph(graph(
            packages=[Package("reqests", maintainers=("alice",))],
            known=["requests"],
        ))
        self.assertIn("typosquat_like", rules(result))
        risk = result.risks[0]
        self.assertEqual(risk.severity, "high")
        self.assertIn("requests", risk.detail)

    def test_unmaintained_boundary(self):
        stale = analyze_graph(graph(packages=[Package("old", last_release_days=400)]), stale_days=365)
        fresh = analyze_graph(graph(packages=[Package("fresh", last_release_days=364)]), stale_days=365)
        undated = analyze_graph(graph(packages=[Package("undated")]), stale_days=365)
        self.assertIn("unmaintained", rules(stale))
        self.assertNotIn("unmaintained", rules(fresh))
        self.assertNotIn("unmaintained", rules(undated))

    def test_unexpected_maintainer(self):
        result = analyze_graph(graph(
            packages=[Package("tool", maintainers=("alice", "bob"))],
        ))
        risk = next(r for r in result.risks if r.rule == "unexpected_maintainer")
        self.assertEqual(risk.severity, "high")
        self.assertIn("bob", risk.detail)

    def test_no_maintainer_check_without_trust_list(self):
        result = analyze_graph(graph(packages=[Package("tool", maintainers=("bob",))], trusted=()))
        self.assertEqual(result.risks, ())

    def test_missing_maintainer_info(self):
        result = analyze_graph(graph(packages=[Package("tool")]))
        risk = next(r for r in result.risks if r.rule == "unknown_maintainer")
        self.assertEqual(risk.severity, "low")

    def test_unknown_dependency(self):
        result = analyze_graph(graph(
            packages=[Package("app", maintainers=("alice",))],
            dependencies=[Dependency("app", "missing-pkg")],
        ))
        risk = next(r for r in result.risks if r.rule == "unknown_dependency")
        self.assertEqual(risk.package, "app")
        self.assertIn("missing-pkg", risk.detail)

    def test_risks_sorted_by_severity_then_rule(self):
        result = analyze_graph(graph(
            packages=[
                Package("old", last_release_days=900),
                Package("reqests", maintainers=("alice",)),
                Package("app", maintainers=("alice",)),
            ],
            known=["requests"],
        ))
        severities = [risk.severity for risk in result.risks]
        self.assertEqual(severities[:1], ["high"])
        self.assertEqual(severities, sorted(severities, key=lambda s: -{"high": 3, "medium": 2, "low": 1}[s]))

    def test_counts_and_score_cap(self):
        packages = [Package(f"bad{i}", maintainers=("bob",)) for i in range(6)]
        result = analyze_graph(graph(packages=packages))
        self.assertEqual(result.counts, {"unexpected_maintainer": 6})
        self.assertEqual(result.score, 100)

    def test_parameter_validation(self):
        with self.assertRaises(ValueError):
            analyze_graph(graph(), stale_days=-1)
        with self.assertRaises(ValueError):
            analyze_graph(graph(), min_name_length=0)

    def test_report_shape(self):
        result = analyze_graph(graph(
            packages=[Package("reqests", maintainers=("alice",))], known=["requests"]
        ))
        report = format_analysis(result)
        self.assertIn("typosquat_like", report)
        self.assertIn("Counts:", report)
        self.assertIn("none", format_analysis(analyze_graph(graph())))


class LoadGraphTests(unittest.TestCase):
    def test_load_valid_graph(self):
        payload = {
            "packages": [
                {"name": "app", "version": "2.0", "maintainers": ["alice"], "last_release_days": 5}
            ],
            "dependencies": [{"source": "app", "target": "app", "kind": "runtime"}],
            "known_names": ["requests"],
            "trusted_maintainers": ["alice"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "graph.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_graph(path)
        self.assertEqual(loaded.packages[0].version, "2.0")
        self.assertEqual(loaded.packages[0].maintainers, ("alice",))
        self.assertEqual(loaded.dependencies[0].target, "app")

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "graph.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_graph(path)

    def test_package_without_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "graph.json"
            path.write_text('{"packages":[{"version":"1.0"}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_graph(path)

    def test_invalid_maintainers_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "graph.json"
            path.write_text('{"packages":[{"name":"app","maintainers":"alice"}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_graph(path)


class CliTests(unittest.TestCase):
    def test_cli_text_and_json(self):
        payload = {
            "packages": [{"name": "reqests", "maintainers": ["alice"]}],
            "known_names": ["requests"],
            "trusted_maintainers": ["alice"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "graph.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            text_buffer = io.StringIO()
            with redirect_stdout(text_buffer):
                self.assertEqual(main(["--graph", str(path)]), 0)
            self.assertIn("typosquat_like", text_buffer.getvalue())

            json_buffer = io.StringIO()
            with redirect_stdout(json_buffer):
                self.assertEqual(main(["--graph", str(path), "--json", "--stale-days", "10"]), 0)
            self.assertEqual(json.loads(json_buffer.getvalue())["counts"]["typosquat_like"], 1)

    def test_cli_missing_graph(self):
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--graph", str(Path(tmp) / "none.json")]), 2)


if __name__ == "__main__":
    unittest.main()
