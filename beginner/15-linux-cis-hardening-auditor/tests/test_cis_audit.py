import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cis_audit import audit, main, parse_sshd_config  # noqa: E402


def by_id(checks):
    return {c.id: c for c in checks}


class AuditTests(unittest.TestCase):
    def test_parse_sshd_config(self):
        config = "# comment\nPermitRootLogin no\nPasswordAuthentication yes\n"
        self.assertEqual(parse_sshd_config(config), {"permitrootlogin": "no", "passwordauthentication": "yes"})

    def test_hardened_snapshot(self):
        checks = by_id(audit(
            {
                "/etc/ssh/sshd_config": "PermitRootLogin no\nPasswordAuthentication no\n",
                "/etc/security/limits.conf": "* hard core 0\n",
                "/etc/sysctl.conf": "net.ipv4.ip_forward=0\n",
            },
            {"/etc/shadow": 0o000, "/etc/passwd": 0o644},
        ))
        self.assertTrue(all(c.status == "pass" for c in checks.values()))

    def test_weak_snapshot(self):
        checks = by_id(audit({}, {"/etc/shadow": 0o644, "/etc/passwd": 0o666}))
        self.assertEqual(checks["SSH-01"].status, "fail")
        self.assertEqual(checks["AUTH-01"].status, "fail")
        self.assertEqual(checks["AUTH-02"].status, "fail")

    def test_missing_modes_warn(self):
        checks = by_id(audit({}))
        self.assertEqual(checks["AUTH-01"].status, "warn")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps({"files": {}, "modes": {}}), encoding="utf-8")
            self.assertEqual(main([str(path)]), 0)


if __name__ == "__main__":
    unittest.main()
