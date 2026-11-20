#!/usr/bin/env python3
"""LSB steganography for uncompressed P6 PPM images.

Hides bytes in the least significant bit of RGB channels. Pure standard
library; no image codecs. PPM is simple enough to parse exactly, which keeps
the implementation auditable and the tests deterministic.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["PPMImage", "StegoError", "hide", "reveal", "capacity_bytes"]

_MAGIC = b"P6"


class StegoError(Exception):
    """Raised for malformed images or payloads that do not fit."""


@dataclass(frozen=True)
class PPMImage:
    width: int
    height: int
    maxval: int
    pixels: bytes  # 3 bytes per pixel, 8-bit RGB

    def to_bytes(self) -> bytes:
        header = f"P6\n{self.width} {self.height}\n{self.maxval}\n".encode("ascii")
        return header + self.pixels

    @classmethod
    def from_bytes(cls, raw: bytes) -> "PPMImage":
        # Tokens: magic, width, height, maxval. Comments start with '#'.
        parts: list[bytes] = []
        i = 0
        while len(parts) < 4:
            if i >= len(raw):
                raise StegoError("truncated PPM header")
            if raw[i : i + 1].isspace():
                i += 1
                continue
            if raw[i : i + 1] == b"#":
                while i < len(raw) and raw[i : i + 1] != b"\n":
                    i += 1
                continue
            start = i
            while i < len(raw) and not raw[i : i + 1].isspace():
                i += 1
            parts.append(raw[start:i])
        if parts[0] != _MAGIC:
            raise StegoError("not a binary PPM (P6) file")
        try:
            width, height, maxval = (int(p) for p in parts[1:])
        except ValueError as exc:
            raise StegoError("invalid PPM dimensions") from exc
        if width <= 0 or height <= 0 or maxval != 255:
            raise StegoError("only 8-bit PPM images are supported")
        # Exactly one whitespace character follows maxval.
        if i >= len(raw) or not raw[i : i + 1].isspace():
            raise StegoError("malformed PPM header")
        i += 1
        pixels = raw[i:]
        expected = width * height * 3
        if len(pixels) != expected:
            raise StegoError(f"expected {expected} pixel bytes, got {len(pixels)}")
        return cls(width, height, maxval, pixels)


def capacity_bytes(image: PPMImage) -> int:
    """Usable payload bytes after reserving 32 bits for the length prefix."""
    return max(0, len(image.pixels) - 32)


def _set_bits(pixels: bytearray, payload: bytes) -> None:
    framed = struct.pack(">I", len(payload)) + payload
    bit_index = 0
    for byte in framed:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            byte_index = bit_index
            if byte_index >= len(pixels):
                raise StegoError("payload exceeds image capacity")
            channel = pixels[byte_index]
            pixels[byte_index] = (channel & 0xFE) | bit
            bit_index += 1


def _get_bits(pixels: bytes, count: int) -> bytes:
    out = bytearray()
    bit_index = 0
    for _ in range(count):
        value = 0
        for _ in range(8):
            byte_index = bit_index
            if byte_index >= len(pixels):
                raise StegoError("truncated hidden payload")
            value = (value << 1) | (pixels[byte_index] & 1)
            bit_index += 1
        out.append(value)
    return bytes(out)


def hide(image: PPMImage, payload: bytes) -> PPMImage:
    if not payload:
        raise StegoError("payload must not be empty")
    if len(payload) > capacity_bytes(image):
        raise StegoError(f"payload of {len(payload)} bytes exceeds capacity {capacity_bytes(image)}")
    pixels = bytearray(image.pixels)
    _set_bits(pixels, payload)
    return PPMImage(image.width, image.height, image.maxval, bytes(pixels))


def reveal(image: PPMImage) -> bytes:
    if len(image.pixels) < 32:
        raise StegoError("image is too small to contain a payload")
    length = struct.unpack(">I", _get_bits(image.pixels, 4))[0]
    if length == 0 or length > capacity_bytes(image):
        raise StegoError("no valid hidden payload found")
    return _get_bits(image.pixels, length + 4)[4:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hide or reveal text in a P6 PPM image.")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("hide", help="embed text from a file")
    enc.add_argument("image", type=Path)
    enc.add_argument("payload", type=Path)
    enc.add_argument("-o", "--output", type=Path, required=True)

    dec = sub.add_parser("reveal", help="extract hidden text")
    dec.add_argument("image", type=Path)
    dec.add_argument("-o", "--output", type=Path, help="write payload to file instead of stdout")

    args = parser.parse_args(argv)
    try:
        image = PPMImage.from_bytes(args.image.read_bytes())
        if args.command == "hide":
            result = hide(image, args.payload.read_bytes())
            args.output.write_bytes(result.to_bytes())
            print(f"hid {args.payload.stat().st_size} bytes in {args.output}")
        else:
            payload = reveal(image)
            if args.output:
                args.output.write_bytes(payload)
            else:
                sys.stdout.buffer.write(payload)
                sys.stdout.buffer.write(b"\n")
        return 0
    except (OSError, StegoError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
