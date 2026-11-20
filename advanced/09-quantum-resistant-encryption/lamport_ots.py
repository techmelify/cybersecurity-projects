#!/usr/bin/env python3
"""Toy Lamport one-time signatures built from SHA-256 and Python's `random`.

EDUCATIONAL DEMONSTRATION ONLY. This is not production post-quantum
cryptography, and each private key may be used for exactly one message.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import random
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEME = "toy-lamport-sha256-v1"
DIGEST_BYTES = hashlib.sha256().digest_size
DIGEST_BITS = DIGEST_BYTES * 8
SECRET_BYTES = 32

__all__ = [
    "PrivateKey",
    "PublicKey",
    "KeyPair",
    "Signature",
    "generate_keypair",
    "public_key_from_private",
    "sign",
    "verify",
    "leaked_secret_indexes",
    "main",
]


@dataclass(frozen=True)
class PrivateKey:
    """Two secret values per message-digest bit position."""

    secrets: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class PublicKey:
    """The SHA-256 image of each private value."""

    hashes: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class KeyPair:
    private: PrivateKey
    public: PublicKey


@dataclass(frozen=True)
class Signature:
    """One revealed secret per message-digest bit position."""

    parts: tuple[bytes, ...]


def _digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _random_secret(rng: random.Random) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(SECRET_BYTES))


def _message_bits(message: bytes) -> tuple[int, ...]:
    bits: list[int] = []
    for byte in _digest(message):
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return tuple(bits)


def public_key_from_private(private: PrivateKey) -> PublicKey:
    """Derive the public key by hashing every private value."""
    if len(private.secrets) != DIGEST_BITS:
        raise ValueError(f"private key must contain {DIGEST_BITS} pairs")
    return PublicKey(
        tuple((_digest(zero), _digest(one)) for zero, one in private.secrets)
    )


def generate_keypair(seed: int) -> KeyPair:
    """Create a deterministic toy key pair from a seeded PRNG.

    The seed must be secret in any real use. Here it exists so tests and demos
    are reproducible; production signatures need a cryptographically secure
    RNG and a reviewed post-quantum scheme such as SLH-DSA or SPHINCS+.
    """
    rng = random.Random(seed)
    secrets: list[tuple[bytes, bytes]] = []
    for _ in range(DIGEST_BITS):
        zero = _random_secret(rng)
        one = _random_secret(rng)
        while one == zero:
            one = _random_secret(rng)
        secrets.append((zero, one))
    private = PrivateKey(tuple(secrets))
    return KeyPair(private, public_key_from_private(private))


def sign(private: PrivateKey, message: bytes) -> Signature:
    """Reveal the secret selected by each bit of the message digest."""
    bits = _message_bits(message)
    if len(private.secrets) != len(bits):
        raise ValueError("private key has an unexpected number of pairs")
    return Signature(
        tuple(private.secrets[index][bit] for index, bit in enumerate(bits))
    )


def verify(public: PublicKey, message: bytes, signature: Signature) -> bool:
    """Check revealed secrets against the public hash images."""
    bits = _message_bits(message)
    if len(public.hashes) != DIGEST_BITS or len(signature.parts) != DIGEST_BITS:
        return False
    return all(
        hmac.compare_digest(
            _digest(signature.parts[index]), public.hashes[index][bit]
        )
        for index, bit in enumerate(bits)
    )


def leaked_secret_indexes(
    signature_a: Signature,
    message_a: bytes,
    signature_b: Signature,
    message_b: bytes,
) -> tuple[int, ...]:
    """Return positions where two signatures reveal different secrets.

    This demonstrates why a Lamport key is one-time: signing two different
    messages discloses both secrets at every differing bit position.
    """
    if len(signature_a.parts) != DIGEST_BITS or len(signature_b.parts) != DIGEST_BITS:
        raise ValueError("both signatures must have the expected length")
    bits_a = _message_bits(message_a)
    bits_b = _message_bits(message_b)
    return tuple(
        index
        for index, (bit_a, bit_b) in enumerate(zip(bits_a, bits_b))
        if bit_a != bit_b and signature_a.parts[index] != signature_b.parts[index]
    )


def _check_scheme(data: Mapping[str, Any]) -> None:
    if not isinstance(data, Mapping) or data.get("scheme") != SCHEME:
        raise ValueError(f"expected scheme {SCHEME!r}")


def _decode_hex(text: Any, field: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError(f"{field} must be a hex string")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{field} is not valid hex") from exc


def _decode_pairs(value: Any, field: str, expected_length: int) -> tuple[tuple[bytes, bytes], ...]:
    if not isinstance(value, list) or len(value) != DIGEST_BITS:
        raise ValueError(f"{field} must be a list of {DIGEST_BITS} pairs")
    pairs: list[tuple[bytes, bytes]] = []
    for index, row in enumerate(value):
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError(f"{field}[{index}] must contain two hex strings")
        first = _decode_hex(row[0], f"{field}[{index}][0]")
        second = _decode_hex(row[1], f"{field}[{index}][1]")
        if len(first) != expected_length or len(second) != expected_length:
            raise ValueError(f"{field}[{index}] has unexpected byte length")
        pairs.append((first, second))
    return tuple(pairs)


def private_key_to_dict(key: PrivateKey) -> dict[str, Any]:
    return {
        "scheme": SCHEME,
        "secrets": [[zero.hex(), one.hex()] for zero, one in key.secrets],
    }


def private_key_from_dict(data: Mapping[str, Any]) -> PrivateKey:
    _check_scheme(data)
    return PrivateKey(_decode_pairs(data.get("secrets"), "secrets", SECRET_BYTES))


def public_key_to_dict(key: PublicKey) -> dict[str, Any]:
    return {
        "scheme": SCHEME,
        "hashes": [[zero.hex(), one.hex()] for zero, one in key.hashes],
    }


def public_key_from_dict(data: Mapping[str, Any]) -> PublicKey:
    _check_scheme(data)
    return PublicKey(_decode_pairs(data.get("hashes"), "hashes", DIGEST_BYTES))


def signature_to_dict(signature: Signature) -> dict[str, Any]:
    return {"scheme": SCHEME, "parts": [part.hex() for part in signature.parts]}


def signature_from_dict(data: Mapping[str, Any]) -> Signature:
    _check_scheme(data)
    value = data.get("parts")
    if not isinstance(value, list) or len(value) != DIGEST_BITS:
        raise ValueError(f"parts must be a list of {DIGEST_BITS} hex strings")
    parts = tuple(
        _decode_hex(item, f"parts[{index}]") for index, item in enumerate(value)
    )
    if any(len(part) != SECRET_BYTES for part in parts):
        raise ValueError("signature parts have an unexpected byte length")
    return Signature(parts)


def _read_json(path: Path) -> Mapping[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Toy one-time signatures (educational, not production crypto)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="create a deterministic toy key pair")
    keygen.add_argument("--seed", type=int, required=True)
    keygen.add_argument("--private-out", type=Path, required=True)
    keygen.add_argument("--public-out", type=Path, required=True)

    sign_parser = sub.add_parser("sign", help="sign one message with a private key")
    sign_parser.add_argument("--private", type=Path, required=True)
    sign_parser.add_argument("--message", required=True)
    sign_parser.add_argument("--output", type=Path, required=True)

    verify_parser = sub.add_parser("verify", help="verify one signature")
    verify_parser.add_argument("--public", type=Path, required=True)
    verify_parser.add_argument("--message", required=True)
    verify_parser.add_argument("--signature", type=Path, required=True)

    reuse = sub.add_parser("reuse-demo", help="show why key reuse leaks secrets")
    reuse.add_argument("--seed", type=int, required=True)
    reuse.add_argument("--message-a", required=True)
    reuse.add_argument("--message-b", required=True)

    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            pair = generate_keypair(args.seed)
            _write_json(args.private_out, private_key_to_dict(pair.private))
            _write_json(args.public_out, public_key_to_dict(pair.public))
            print("wrote toy key pair; keep the private file secret")
            return 0

        if args.command == "sign":
            private = private_key_from_dict(_read_json(args.private))
            signature = sign(private, args.message.encode("utf-8"))
            _write_json(args.output, signature_to_dict(signature))
            print(f"wrote one-time signature to {args.output}")
            return 0

        if args.command == "verify":
            public = public_key_from_dict(_read_json(args.public))
            signature = signature_from_dict(_read_json(args.signature))
            valid = verify(public, args.message.encode("utf-8"), signature)
            print("valid" if valid else "invalid")
            return 0 if valid else 1

        pair = generate_keypair(args.seed)
        signature_a = sign(pair.private, args.message_a.encode("utf-8"))
        signature_b = sign(pair.private, args.message_b.encode("utf-8"))
        leaked = leaked_secret_indexes(
            signature_a,
            args.message_a.encode("utf-8"),
            signature_b,
            args.message_b.encode("utf-8"),
        )
        print(f"reuse would reveal {len(leaked)} distinct secret positions")
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
