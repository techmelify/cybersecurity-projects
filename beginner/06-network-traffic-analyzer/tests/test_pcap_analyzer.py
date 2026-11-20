import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pcap_analyzer import parse_pcap, summarize, main  # noqa: E402


def ipv4(text):
    return bytes(int(part) for part in text.split("."))


def frame(src, dst, protocol, sport=None, dport=None):
    transport = b""
    if protocol == 6:
        transport = struct.pack("!HHIIHHHH", sport, dport, 1, 0, 0x50, 8192, 0, 0)
    elif protocol == 17:
        transport = struct.pack("!HHHH", sport, dport, 8, 0)
    total = 20 + len(transport)
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, total)
    ip[8] = 64
    ip[9] = protocol
    ip[12:16] = ipv4(src)
    ip[16:20] = ipv4(dst)
    eth = b"\x00" * 12 + b"\x08\x00"
    return eth + bytes(ip) + transport


def write_pcap(path, frames):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = []
    for i, data in enumerate(frames):
        records.append(struct.pack("<IIII", 1700000000 + i, 0, len(data), len(data)) + data)
    Path(path).write_bytes(header + b"".join(records))


class PcapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "sample.pcap"

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_tcp_and_udp(self):
        write_pcap(self.path, [
            frame("10.0.0.1", "10.0.0.2", 6, 12345, 443),
            frame("10.0.0.2", "10.0.0.1", 6, 443, 12345),
            frame("10.0.0.1", "8.8.8.8", 17, 53000, 53),
        ])
        packets = parse_pcap(self.path)
        self.assertEqual(len(packets), 3)
        self.assertEqual(packets[0].protocol, "TCP")
        self.assertEqual(packets[0].dst_port, 443)
        self.assertEqual(packets[2].protocol, "UDP")
        self.assertEqual(packets[2].dst, "8.8.8.8")

    def test_summary(self):
        write_pcap(self.path, [
            frame("10.0.0.1", "10.0.0.2", 6, 1111, 80),
            frame("10.0.0.1", "10.0.0.2", 6, 1111, 80),
            frame("10.0.0.3", "10.0.0.2", 17, 2222, 53),
        ])
        summary = summarize(parse_pcap(self.path))
        self.assertEqual(summary.packet_count, 3)
        self.assertEqual(summary.protocols["TCP"], 2)
        self.assertEqual(summary.protocols["UDP"], 1)
        self.assertEqual(summary.top_talkers[0], ("10.0.0.1", 2))

    def test_bad_magic(self):
        self.path.write_bytes(b"not a pcap" * 10)
        with self.assertRaises(ValueError):
            parse_pcap(self.path)

    def test_short_file(self):
        self.path.write_bytes(b"abc")
        with self.assertRaises(ValueError):
            parse_pcap(self.path)

    def test_cli_text(self):
        write_pcap(self.path, [frame("10.0.0.1", "10.0.0.2", 6, 1, 80)])
        self.assertEqual(main([str(self.path)]), 0)

    def test_cli_json(self):
        write_pcap(self.path, [frame("10.0.0.1", "10.0.0.2", 1)])
        self.assertEqual(main([str(self.path), "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
