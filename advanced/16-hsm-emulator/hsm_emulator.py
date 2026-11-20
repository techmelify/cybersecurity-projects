#!/usr/bin/env python3
"""Software HSM emulator for a synthetic, offline lab.

Keys are derived and wrapped with AES-GCM under a master key, and messages are
signed with HMAC-SHA-256. Plaintext keys stay inside the HSM object; the public
API returns wrapped blobs, signatures, identifiers, and one-way fingerprints.
There is no hardware, persistent credential store, or network access.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - exercised only without the dependency
    InvalidTag = ValueError  # type: ignore[assignment,misc]
    AESGCM = None  # type: ignore[assignment]

__all__ = ["WrappedKey", "Signature", "HSM"]

# A synthetic lab default. Never use this constant to protect real data.
_LAB_MASTER_KEY = hashlib.sha256(b"synthetic hsm lab master key / not a credential").digest()
_AAD_PREFIX = b"hsm-lab-v1\x00"
_NONCE_PREFIX = b"nonce\x00"


@dataclass(frozen=True)
class WrappedKey:
    """AES-GCM wrapped key material. No plaintext field exists by design."""

    key_id: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    algorithm: str = "AES-GCM-256"

    def to_dict(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag.hex(),
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "WrappedKey":
        return cls(
            key_id=str(data["key_id"]),
            nonce=bytes.fromhex(str(data["nonce"])),
            ciphertext=bytes.fromhex(str(data["ciphertext"])),
            tag=bytes.fromhex(str(data["tag"])),
            algorithm=str(data.get("algorithm", "AES-GCM-256")),
        )


@dataclass(frozen=True)
class Signature:
    """Detached HMAC signature for one message."""

    key_id: str
    signature: bytes
    algorithm: str = "HMAC-SHA-256"

    def to_dict(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "signature": self.signature.hex(),
            "algorithm": self.algorithm,
        }


class HSM:
    """In-memory emulator. Key bytes are private and never returned."""

    def __init__(self, master_key: bytes | None = None) -> None:
        if AESGCM is None:  # pragma: no cover
            raise RuntimeError("the 'cryptography' package is required for AES-GCM wrapping")
        key = _LAB_MASTER_KEY if master_key is None else bytes(master_key)
        if len(key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._master_key = key
        self._keys: dict[str, bytes] = {}

    def _aead(self) -> "AESGCM":
        return AESGCM(self._master_key)

    @staticmethod
    def _nonce_for(key_id: str) -> bytes:
        return hashlib.sha256(_NONCE_PREFIX + key_id.encode("utf-8")).digest()[:12]

    @staticmethod
    def _associated_data(key_id: str) -> bytes:
        return _AAD_PREFIX + key_id.encode("utf-8")

    def _derive(self, key_id: str, length: int) -> bytes:
        seed = self._master_key + b"\x00key\x00" + key_id.encode("utf-8")
        seed += b"\x00" + str(length).encode("ascii")
        return hashlib.sha256(seed).digest()[:length]

    def generate_key(self, key_id: str, length: int = 32) -> WrappedKey:
        """Create a synthetic key, store it privately, and return its wrapper."""
        if not key_id or not isinstance(key_id, str):
            raise ValueError("key_id must be a non-empty string")
        if not 16 <= length <= 64:
            raise ValueError("key length must be between 16 and 64 bytes")
        plaintext = self._derive(key_id, length)
        self._keys[key_id] = plaintext
        nonce = self._nonce_for(key_id)
        blob = self._aead().encrypt(nonce, plaintext, self._associated_data(key_id))
        return WrappedKey(key_id, nonce, blob[:-16], blob[-16:])

    def restore_key(self, wrapped: WrappedKey) -> str:
        """Unwrap a key into private storage and return only its identifier."""
        if wrapped.algorithm != "AES-GCM-256":
            raise ValueError("unsupported wrapping algorithm")
        plaintext = self._aead().decrypt(
            wrapped.nonce,
            wrapped.ciphertext + wrapped.tag,
            self._associated_data(wrapped.key_id),
        )
        self._keys[wrapped.key_id] = plaintext
        return wrapped.key_id

    def sign(self, key_id: str, message: bytes) -> Signature:
        if key_id not in self._keys:
            raise KeyError(f"unknown key: {key_id}")
        digest = hmac.new(self._keys[key_id], bytes(message), hashlib.sha256).digest()
        return Signature(key_id, digest)

    def verify(self, key_id: str, message: bytes, signature: Signature | bytes) -> bool:
        candidate = signature.signature if isinstance(signature, Signature) else bytes(signature)
        expected = self.sign(key_id, message).signature
        return hmac.compare_digest(candidate, expected)

    def fingerprint(self, key_id: str) -> str:
        """One-way identifier for a stored key (never the key itself)."""
        if key_id not in self._keys:
            raise KeyError(f"unknown key: {key_id}")
        return hashlib.sha256(self._keys[key_id]).hexdigest()

    def list_key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def master_fingerprint(self) -> str:
        return hashlib.sha256(self._master_key).hexdigest()


def _print(payload: Mapping[str, object]) -> None:
    print(json.dumps(payload, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline software HSM emulator.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="create a synthetic wrapped key")
    generate.add_argument("--key-id", required=True)
    generate.add_argument("--length", type=int, default=32)
    generate.add_argument("--out", type=Path, help="write wrapper JSON to this file")

    sign = subparsers.add_parser("sign", help="sign a message with a restored wrapper")
    sign.add_argument("--wrapped", type=Path, required=True)
    sign.add_argument("--message", required=True)

    verify = subparsers.add_parser("verify", help="verify a detached signature")
    verify.add_argument("--wrapped", type=Path, required=True)
    verify.add_argument("--message", required=True)
    verify.add_argument("--signature", required=True, help="hex signature")

    args = parser.parse_args(argv)
    hsm = HSM()
    try:
        if args.command == "generate":
            wrapped = hsm.generate_key(args.key_id, args.length)
            payload = wrapped.to_dict()
            if args.out:
                args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            wrapped = WrappedKey.from_dict(json.loads(args.wrapped.read_text(encoding="utf-8")))
            hsm.restore_key(wrapped)
            message = args.message.encode("utf-8")
            if args.command == "sign":
                payload = hsm.sign(wrapped.key_id, message).to_dict()
            else:
                payload = {"valid": hsm.verify(wrapped.key_id, message, bytes.fromhex(args.signature))}
    except (ValueError, KeyError, InvalidTag) as error:
        parser.error(str(error))
    _print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
