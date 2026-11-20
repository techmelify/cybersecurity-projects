import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from graphql_analyzer import analyze_snapshot, main, measure_query, parse_snapshot, tokenize  # noqa: E402


def ids(findings):
    return [finding.id for finding in findings]


def make_snapshot(queries, policy=None):
    return {
        "queries": queries,
        "server_policy": policy if policy is not None else {"max_depth": 8, "max_aliases": 10, "max_batch_size": 5},
    }


class GraphQLAnalyzerTests(unittest.TestCase):
    def test_tokenize_ignores_braces_in_strings_and_comments(self):
        tokens = tokenize('# { not a brace }\n{ field(arg: "a}b") }')
        self.assertEqual([token.value for token in tokens if token.value in "{()}"], ["{", "(", ")", "}"])

    def test_measure_query_depth(self):
        metrics = measure_query("query deep { a { b { c { id } } } }", "deep")
        self.assertEqual(metrics.max_depth, 4)
        self.assertEqual(metrics.alias_count, 0)

    def test_measure_aliases_and_introspection(self):
        metrics = measure_query(
            "query Q($id: ID!) { first: user(id: $id) { name } __schema { types { name } } }",
            "Q",
        )
        self.assertEqual(metrics.alias_count, 1)
        self.assertEqual(metrics.introspection_fields, ("__schema",))

    def test_deep_query_and_introspection_findings(self):
        text = "query deep { " + "a { " * 9 + "id" + " }" * 9 + " }"
        findings = analyze_snapshot(parse_snapshot(make_snapshot([{"name": "deep", "query": text}])))
        self.assertEqual(ids(findings), ["GQL-001"])
        deep = next(finding for finding in findings if finding.id == "GQL-001")
        self.assertIn("deep=10", deep.detail)

    def test_alias_and_batch_findings(self):
        fields = " ".join(f"alias{i}: user {{ id }}" for i in range(11))
        queries = [{"name": "aliases", "query": "query aliases { " + fields + " }"}]
        queries.extend({"name": f"small{i}", "query": "{ viewer { id } }"} for i in range(5))
        findings = analyze_snapshot(parse_snapshot(make_snapshot(queries)))
        self.assertEqual(ids(findings), ["GQL-003", "GQL-004"])

    def test_missing_and_permissive_depth_policy(self):
        missing = analyze_snapshot(parse_snapshot(make_snapshot(["{ viewer { id } }"], {})))
        self.assertEqual([f.severity for f in missing if f.id == "GQL-005"], ["high"])
        permissive = analyze_snapshot(
            parse_snapshot(make_snapshot(["{ viewer { id } }"], {"max_depth": 50}))
        )
        self.assertEqual([f.severity for f in permissive if f.id == "GQL-005"], ["medium"])

    def test_clean_snapshot_has_no_findings(self):
        findings = analyze_snapshot(
            parse_snapshot(
                make_snapshot([{"name": "dashboard", "query": "query dashboard { user { id posts { title } } }"}])
            )
        )
        self.assertEqual(findings, [])

    def test_cli_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(
                json.dumps(make_snapshot(["query s { __schema { types { name } } }"])),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual([item["id"] for item in payload], ["GQL-002"])


if __name__ == "__main__":
    unittest.main()
