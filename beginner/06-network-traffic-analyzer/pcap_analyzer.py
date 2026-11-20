#!/usr/bin/env python3
"""Offline PCAP parser and traffic summarizer.

Pure standard library. Parses classic libpcap files; no live capture, no
promiscuous mode, no admin rights required. Synthetic fixtures make tests
deterministic.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = ["Packet", "TrafficSummary", "parse_pcap", "summarize"]

_GLOBAL_HEADER = struct.Struct("<IHHIIII")
_RECORD_HEADER = struct.Struct("<IIII")
_ETHERTYPE_IPV4 = 0x0800


@dataclass(frozen=True)
class Packet:
    timestamp: float
    protocol: str
    src: str
    dst: str
    src_port: int | None
    dst_port: int | None
    length: int


@dataclass(frozen=True)
class TrafficSummary:
    packet_count: int
    protocols: dict[str, int]
    top_talkers: tuple[tuple[str, int], ...]
    top_conversations: tuple[tuple[str, int], ...]

    def render(self) -> str:
        lines = [f"packets: {self.packet_count}", "protocols:"]
        lines.extend(f"  {name}: {count}" for name, count in sorted(self.protocols.items()))
        lines.append("top talkers:")
        lines.extend(f"  {ip}: {count}" for ip, count in self.top_talkers)
        lines.append("top conversations:")
        lines.extend(f"  {pair}: {count}" for pair, count in self.top_conversations)
        return "\n".join(lines)


def _ipv4(data: bytes) -> str:
    return ".".join(str(b) for b in data[:4])


def parse_pcap(path: Path) -> list[Packet]:
    """Parse a classic little-endian libpcap file into Packet records."""
    raw = Path(path).read_bytes()
    if len(raw) < _GLOBAL_HEADER.size:
        raise ValueError("file is too short to be a pcap")
    magic, _, _, _, _, _, network = _GLOBAL_HEADER.unpack_from(raw)
    if magic != 0xA1B2C3D4:
        raise ValueError("unsupported pcap magic (expected little-endian 0xa1b2c3d4)")
    if network != 1:
        raise ValueError(f"unsupported link type {network} (expected Ethernet)")

    offset = _GLOBAL_HEADER.size
    packets: list[Packet] = []
    while offset + _RECORD_HEADER.size <= len(raw):
        sec, usec, incl, _orig = _RECORD_HEADER.unpack_from(raw, offset)
        offset += _RECORD_HEADER.size
        frame = raw[offset : offset + incl]
        offset += incl
        if len(frame) < 14 or int.from_bytes(frame[12:14], "big") != _ETHERTYPE_IPV4:
            continue
        ip = frame[14:]
        if len(ip) < 20:
            continue
        proto_num = ip[9]
        src, dst = _ipv4(ip[12:16]), _ipv4(ip[16:20])
        ihl = (ip[0] & 0x0F) * 4
        transport = ip[ihl:]
        sport = dport = None
        if proto_num == 6 and len(transport) >= 4:  # TCP
            sport, dport = struct.unpack_from("!HH", transport)
        elif proto_num == 17 and len(transport) >= 4:  # UDP
            sport, dport = struct.unpack_from("!HH", transport)
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))
        packets.append(Packet(sec + usec / 1_000_000, protocol, src, dst, sport, dport, incl))
    return packets


def summarize(packets: list[Packet], top_n: int = 5) -> TrafficSummary:
    protocols = Counter(p.protocol for p in packets)
    talkers = Counter()
    conversations = Counter()
    for p in packets:
        talkers[p.src] += 1
        pair = f"{p.src}:{p.src_port or '-'} -> {p.dst}:{p.dst_port or '-'}"
        conversations[pair] += 1
    return TrafficSummary(
        len(packets),
        dict(protocols),
        tuple(talkers.most_common(top_n)),
        tuple(conversations.most_common(top_n)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize a classic libpcap file offline.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--top", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        result = summarize(parse_pcap(args.pcap), args.top)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print(result.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
