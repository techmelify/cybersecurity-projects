#!/usr/bin/env python3
"""Base64 encoder/decoder with strict validation and URL-safe mode."""

from __future__ import annotations

import argparse
import base64
import binascii
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CodecError", "encode_text", "decode_text", "encode_file", "decode_file"]

_URLSAFE_TO_STD = str.maketrans("-_", "+/")


def _decode_raw(value: str, urlsafe: bool) -> bytes:
    normalized = value.translate(_URLSAFE_TO_STD) if urlsafe else value
    return base64.b64decode(normalized.encode("ascii"), validate=True)


class CodecError(Exception):
    """Raised for invalid base64 input."""


@dataclass(frozen=True)
class Encoded:
    value: str
    urlsafe: bool


def encode_text(text: str, *, urlsafe: bool = False) -> Encoded:
    raw = text.encode("utf-8")
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return Encoded(encoder(raw).decode("ascii"), urlsafe)


def decode_text(value: str, *, urlsafe: bool = False) -> str:
    try:
        return _decode_raw(value, urlsafe).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise CodecError("invalid base64 or UTF-8 input") from exc


def encode_file(path: Path, *, urlsafe: bool = False) -> str:
    raw = Path(path).read_bytes()
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(raw).decode("ascii")


def decode_file(value: str, path: Path, *, urlsafe: bool = False) -> int:
    try:
        raw = _decode_raw(value, urlsafe)
    except (binascii.Error, ValueError) as exc:
        raise CodecError("invalid base64 input") from exc
    Path(path).write_bytes(raw)
    return len(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Base64 encode/decode text or files.")
    parser.add_argument("--urlsafe", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode")
    enc.add_argument("text", nargs="?")
    enc.add_argument("--file", type=Path)

    dec = sub.add_parser("decode")
    dec.add_argument("value", nargs="?")
    dec.add_argument("--file-in", type=Path, help="file containing base64 text")
    dec.add_argument("--file-out", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "encode":
            if args.file:
                print(encode_file(args.file, urlsafe=args.urlsafe))
            elif args.text is not None:
                print(encode_text(args.text, urlsafe=args.urlsafe).value)
            else:
                parser.error("provide text or --file")
        else:
            value = args.file_in.read_text(encoding="ascii").strip() if args.file_in else args.value
            if value is None:
                parser.error("provide a value or --file-in")
            if args.file_out:
                size = decode_file(value, args.file_out, urlsafe=args.urlsafe)
                print(f"wrote {size} bytes")
            else:
                print(decode_text(value, urlsafe=args.urlsafe))
        return 0
    except (CodecError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
