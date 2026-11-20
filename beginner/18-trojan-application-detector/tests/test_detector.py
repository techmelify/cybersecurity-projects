import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector import main, scan_artifact  # noqa: E402


class DetectorTests(unittest.TestCase):
    def test_clean_app(self):
        files = {"main.py": "print('hello')\n"}
        self.assertEqual(scan_artifact("clean", files), [])

    def test_execution_marker(self):
        files = {"main.py": "subprocess.run(['echo', 'hi'])\n"}
        findings = scan_artifact("app", files)
        self.assertTrue(any(f.severity == "medium" for f in findings))

    def test_persistence_marker(self):
        files = {"install.sh": "systemctl enable evil.service\n"}
        findings = scan_artifact("app", files)
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_combination_escalation(self):
        files = {
            "loader.py": "exec(base64.b64decode(x))\nsubprocess.run(cmd, shell=True)\n",
            "install.sh": "crontab -l\n",
        }
        findings = scan_artifact("app", files)
        self.assertTrue(any(f.reason.startswith("execution + decoding") for f in findings))

    def test_packer_low(self):
        findings = scan_artifact("app", {"README": "packed with UPX"})
        self.assertTrue(any(f.severity == "low" for f in findings))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "apps.json"
            path.write_text(json.dumps({"app": {"main.py": "print(1)"}}), encoding="utf-8")
            self.assertEqual(main([str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
