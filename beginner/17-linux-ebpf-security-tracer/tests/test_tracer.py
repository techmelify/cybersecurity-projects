import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tracer import analyze, main  # noqa: E402


class TracerTests(unittest.TestCase):
    def test_clean_exec(self):
        events = [{"type": "exec", "comm": "python3", "path": "/opt/app/main.py", "parent_comm": "systemd", "uid": 1000}]
        self.assertEqual(analyze(events), [])

    def test_writable_path(self):
        events = [{"type": "exec", "comm": "x", "path": "/tmp/payload", "uid": 1000}]
        alerts = analyze(events)
        self.assertEqual(alerts[0].severity, "high")

    def test_web_server_shell(self):
        events = [{"type": "exec", "comm": "bash", "path": "/bin/bash", "parent_comm": "nginx", "uid": 33}]
        self.assertTrue(any("web server" in a.reason for a in analyze(events)))

    def test_root_network_utility(self):
        events = [{"type": "exec", "comm": "curl", "path": "/usr/bin/curl", "uid": 0}]
        self.assertTrue(any("root" in a.reason for a in analyze(events)))

    def test_public_ip(self):
        events = [{"type": "network", "dst": "8.8.8.8"}]
        self.assertTrue(any("public IP" in a.reason for a in analyze(events)))

    def test_private_ip_ignored(self):
        events = [{"type": "network", "dst": "10.0.0.5"}]
        self.assertEqual(analyze(events), [])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(json.dumps({"type": "exec", "comm": "x", "path": "/tmp/x", "uid": 1000}) + "\n", encoding="utf-8")
            self.assertEqual(main([str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
