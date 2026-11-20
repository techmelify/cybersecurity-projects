import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stateless_scanner import (  # noqa: E402
    DEFAULT_CATALOG,
    HostFinding,
    PortFinding,
    RiskEntry,
    demo_scan,
    load_catalog,
    main,
    match_risks,
    parse_scan,
)


class ScannerTests(unittest.TestCase):
    def test_parse_host_without_name(self):
        hosts = parse_scan("Nmap scan report for 192.0.2.10\n")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].address, "192.0.2.10")
        self.assertEqual(hosts[0].hostname, "")

    def test_parse_host_with_name_in_parentheses(self):
        hosts = parse_scan("Nmap scan report for router.lab (192.0.2.1)\n")
        self.assertEqual(hosts[0].address, "192.0.2.1")
        self.assertEqual(hosts[0].hostname, "router.lab")

    def test_parse_port_fields(self):
        hosts = parse_scan("Nmap scan report for 192.0.2.10\n22/tcp open ssh OpenSSH 9.0\n")
        port = hosts[0].ports[0]
        self.assertEqual(port, PortFinding(22, "tcp", "open", "ssh", "OpenSSH 9.0"))

    def test_header_and_comments_ignored(self):
        text = "Nmap scan report for 192.0.2.10\nPORT STATE SERVICE VERSION\n# note\nHost is up.\n23/tcp open telnet\n"
        hosts = parse_scan(text)
        self.assertEqual([p.port for p in hosts[0].ports], [23])

    def test_multiple_hosts(self):
        text = "Nmap scan report for 192.0.2.1\n80/tcp open http\n\nNmap scan report for 192.0.2.2\n22/tcp open ssh\n"
        hosts = parse_scan(text)
        self.assertEqual([h.address for h in hosts], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual([len(h.ports) for h in hosts], [1, 1])

    def test_port_validation(self):
        with self.assertRaises(ValueError):
            PortFinding(70000, "tcp", "open", "x")

    def test_default_catalog_matches_telnet(self):
        hosts = parse_scan("Nmap scan report for 192.0.2.10\n23/tcp open telnet\n")
        risks = match_risks(hosts)
        self.assertEqual(len(risks), 1)
        self.assertEqual((risks[0].severity, risks[0].port), ("critical", 23))

    def test_port_specific_entry(self):
        catalog = (RiskEntry("ssh", "high", "nonstandard port", frozenset({2222})),)
        hosts = parse_scan("Nmap scan report for h\n22/tcp open ssh\n2222/tcp open ssh\n")
        risks = match_risks(hosts, catalog)
        self.assertEqual([r.port for r in risks], [2222])

    def test_only_open_ports_become_risks(self):
        hosts = parse_scan("Nmap scan report for h\n23/tcp closed telnet\n80/tcp filtered http\n")
        self.assertEqual(match_risks(hosts), ())

    def test_min_severity_filter(self):
        hosts = parse_scan("Nmap scan report for h\n22/tcp open ssh\n80/tcp open http\n23/tcp open telnet\n")
        risks = match_risks(hosts, DEFAULT_CATALOG, "high")
        self.assertEqual([r.service for r in risks], ["telnet"])

    def test_load_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps([{"service": "http", "severity": "high", "note": "lab rule", "ports": [8080]}]), encoding="utf-8")
            catalog = load_catalog(path)
            self.assertEqual(catalog[0].ports, frozenset({8080}))
            self.assertEqual(catalog[0].note, "lab rule")

    def test_cli_demo_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--demo", "--json", "--min-severity", "high"])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        services = {r["service"] for r in report["risks"]}
        self.assertEqual(services, {"telnet", "redis"})
        self.assertEqual(len(report["hosts"]), 2)

    def test_cli_rejects_unknown_severity(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--demo", "--min-severity", "urgent"]), 1)

    def test_demo_scan_is_stable(self):
        self.assertEqual(demo_scan(), demo_scan())


if __name__ == "__main__":
    unittest.main()
