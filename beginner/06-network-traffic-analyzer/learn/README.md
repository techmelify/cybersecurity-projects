# Learn — packet capture parsing

## File format

A classic pcap file has a 24-byte global header followed by repeated 16-byte record headers, each preceded by the captured frame bytes. The magic number also tells you the byte order of the whole file.

## Layer decoding

Ethernet frames carry a 2-byte EtherType; `0x0800` means IPv4. The IPv4 header gives the protocol number and source/destination addresses. TCP and UDP headers then provide ports. Each step is a fixed offset read, which is why `struct` is ideal.

## Why offline parsing

Live capture needs privileges and a real interface. Tests that depend on either are flaky. Writing synthetic frames makes every assertion deterministic and lets the parser be used on evidence files long after capture.

## Exercises

- Add IPv6 and pcapng support.
- Parse DNS queries from UDP port 53 payloads.
- Detect scanning behaviour by counting SYN packets without ACKs.
