import asyncio
import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from port_scanner import PortResult, parse_ports, scan, scan_port  # noqa: E402


class ParseTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range(self):
        self.assertEqual(parse_ports("10-13"), [10, 11, 12, 13])

    def test_list_with_duplicates(self):
        self.assertEqual(parse_ports("443, 80, 443"), [80, 443])

    def test_invalid(self):
        for spec in ("0", "65536", "100-10", "abc", "1-70000"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                parse_ports(spec)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port = self.listener.getsockname()[1]

    def tearDown(self):
        self.listener.close()

    def test_open_port(self):
        result = asyncio.run(scan_port("127.0.0.1", self.port, timeout=1.0))
        self.assertTrue(result.open)
        self.assertIsInstance(result.service, str)

    def test_closed_port(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
        probe.close()
        result = asyncio.run(scan_port("127.0.0.1", closed, timeout=0.25))
        self.assertFalse(result.open)

    def test_scan_batch(self):
        results = asyncio.run(scan("127.0.0.1", [self.port], timeout=1.0, concurrency=2))
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].open)

    def test_result_is_frozen(self):
        result = PortResult(80, True, "http")
        with self.assertRaises(Exception):
            result.port = 81


if __name__ == "__main__":
    unittest.main()
