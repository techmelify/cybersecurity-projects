import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from docker_audit import audit, main, parse_config_assignments, parse_dockerfile_instructions, parse_snapshot  # noqa: E402


def ids(findings):
    return [finding.id for finding in findings]


class DockerAuditTests(unittest.TestCase):
    def test_parse_dockerfile_instructions(self):
        instructions = parse_dockerfile_instructions(
            "# comment\nFROM alpine:3.19\nENV A=1 \\\n    B=2\nUSER 10001\n"
        )
        self.assertEqual(
            instructions,
            (("FROM", "alpine:3.19"), ("ENV", "A=1 B=2"), ("USER", "10001")),
        )

    def test_root_user_findings(self):
        explicit = audit(parse_snapshot({"dockerfile": "FROM alpine:3.19\nUSER root\n"}))
        self.assertEqual([(f.id, f.severity) for f in explicit if f.id == "DOCK-001"], [("DOCK-001", "high")])
        implicit = audit(parse_snapshot({"dockerfile": "FROM alpine:3.19\n"}))
        self.assertEqual([(f.id, f.severity) for f in implicit if f.id == "DOCK-001"], [("DOCK-001", "medium")])

    def test_privileged_mode(self):
        findings = audit(parse_snapshot({"config": "services:\n  app:\n    privileged: true\n"}))
        self.assertIn("DOCK-002", ids(findings))

    def test_host_mounts_and_port_mapping(self):
        findings = audit(
            parse_snapshot(
                {
                    "dockerfile": "FROM alpine:3.19\nUSER 10001\n",
                    "config": (
                        "services:\n  app:\n    volumes:\n"
                        "      - /var/run/docker.sock:/var/run/docker.sock\n"
                        "      - ./data:/data\n"
                        "    ports:\n      - \"8080:80\"\n"
                    ),
                }
            )
        )
        mounts = [finding for finding in findings if finding.id == "DOCK-003"]
        self.assertEqual(len(mounts), 2)
        self.assertEqual(sorted(finding.severity for finding in mounts), ["high", "medium"])
        self.assertFalse(any("8080" in finding.detail for finding in mounts))

    def test_latest_tags(self):
        findings = audit(
            parse_snapshot(
                {
                    "dockerfile": (
                        "FROM ubuntu:latest\nFROM scratch\nFROM alpine@sha256:demo\nUSER 10001\n"
                    ),
                    "config": "services:\n  worker:\n    image: nginx\n",
                }
            )
        )
        tags = [finding for finding in findings if finding.id == "DOCK-004"]
        self.assertEqual(len(tags), 3)
        self.assertTrue(any("uses :latest" in finding.detail for finding in tags))
        self.assertFalse(any("sha256" in finding.detail for finding in tags))

    def test_secret_values_are_not_printed(self):
        findings = audit(
            parse_snapshot(
                {
                    "dockerfile": (
                        "FROM alpine:3.19\nUSER 10001\nENV API_TOKEN=demo-not-real\n"
                        "ARG DB_PASSWORD=demo-not-real\n"
                    ),
                    "config": "services:\n  app:\n    environment:\n      - CLIENT_SECRET=demo-not-real\n",
                }
            )
        )
        secrets = [finding for finding in findings if finding.id == "DOCK-005"]
        self.assertEqual(len(secrets), 3)
        self.assertTrue(all("demo-not-real" not in finding.detail for finding in secrets))
        self.assertTrue(any("API_TOKEN" in finding.detail for finding in secrets))

    def test_clean_snapshot_has_no_findings(self):
        findings = audit(
            parse_snapshot(
                {
                    "dockerfile": "FROM alpine:3.19\nUSER 10001\n",
                    "config": (
                        "services:\n  app:\n    image: alpine:3.19\n"
                        "    privileged: false\n    user: \"10001:10001\"\n"
                    ),
                }
            )
        )
        self.assertEqual(findings, [])

    def test_parse_config_assignments_and_cli(self):
        assignments = parse_config_assignments('services:\n  app:\n    image: "alpine:3.19"\n')
        self.assertIn(("image", "alpine:3.19"), assignments)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(
                json.dumps({"dockerfile": "FROM alpine:latest\n"}),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = main([str(path), "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertIn("DOCK-001", [item["id"] for item in payload])
            self.assertIn("DOCK-004", [item["id"] for item in payload])


if __name__ == "__main__":
    unittest.main()
