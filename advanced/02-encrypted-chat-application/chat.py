#!/usr/bin/env python3
"""Local, file-backed encrypted chat simulation.

Uses AES-256-GCM with a fresh nonce per message and a shared *lab* key. There
is no server, no socket, and no real credential material. Keys are never
printed, logged, or written into the message store.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "LAB_PHRASE",
    "ChatMessage",
    "StoredRecord",
    "ChatStore",
    "AuthError",
    "StoreFormatError",
    "DuplicateSequenceError",
    "derive_lab_key",
    "load_key_file",
    "write_key_file",
    "encrypt_payload",
    "decrypt_payload",
    "main",
]

_FORMAT = "lab-chat-v1"
_AAD_PREFIX = b"lab-chat-v1:"
_NONCE_BYTES = 12
_KEY_BYTES = 32

# Public teaching key. Derived deterministically so labs are reproducible; it
# is deliberately NOT a secret and must never protect real messages.
LAB_PHRASE = "cybersecurity-projects/shared-lab-key/v1"


class AuthError(Exception):
    """Raised when a message cannot be authenticated with the supplied key."""


class StoreFormatError(Exception):
    """Raised when the chat JSON file is not a supported store."""


class DuplicateSequenceError(Exception):
    """Raised when a message sequence number is reused."""


@dataclass(frozen=True)
class ChatMessage:
    """A plaintext message with caller-supplied ordering metadata."""

    sequence: int
    sender: str
    body: str
    timestamp: str

    def __post_init__(self) -> None:
        if self.sequence < 1:
            raise ValueError("sequence must be at least 1")
        if not self.sender.strip():
            raise ValueError("sender must not be empty")
        if not self.timestamp.strip():
            raise ValueError("timestamp must not be empty")


@dataclass(frozen=True)
class StoredRecord:
    """The only message data persisted in the JSON file."""

    sequence: int
    nonce: str
    ciphertext: str


def derive_lab_key(phrase: str = LAB_PHRASE) -> bytes:
    """Derive the fixed 32-byte lab key from a public phrase."""
    if not phrase:
        raise ValueError("phrase must not be empty")
    return hashlib.sha256(phrase.encode("utf-8")).digest()


def load_key_file(path: Path) -> bytes:
    """Read a 32-byte hex key from disk without echoing its contents."""
    text = Path(path).read_text(encoding="utf-8").strip()
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("key file must contain hexadecimal characters") from exc
    if len(key) != _KEY_BYTES:
        raise ValueError(f"key file must contain {_KEY_BYTES} bytes ({_KEY_BYTES * 2} hex characters)")
    return key


def write_key_file(path: Path) -> None:
    """Generate and store a lab key; the key itself is never printed."""
    target = Path(path)
    if target.exists():
        raise ValueError("key file already exists")
    target.write_text(os.urandom(_KEY_BYTES).hex() + "\n", encoding="utf-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _aad(sequence: int) -> bytes:
    return _AAD_PREFIX + str(sequence).encode("ascii")


def encrypt_payload(key: bytes, nonce: bytes, message: ChatMessage) -> bytes:
    """Encrypt a whole message, binding its sequence number as AAD."""
    if len(key) != _KEY_BYTES:
        raise ValueError(f"key must be {_KEY_BYTES} bytes")
    if len(nonce) != _NONCE_BYTES:
        raise ValueError(f"nonce must be {_NONCE_BYTES} bytes")
    payload = {
        "sequence": message.sequence,
        "sender": message.sender,
        "body": message.body,
        "timestamp": message.timestamp,
    }
    return AESGCM(key).encrypt(nonce, json.dumps(payload, sort_keys=True).encode("utf-8"), _aad(message.sequence))


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes, sequence: int) -> ChatMessage:
    """Authenticate and decode a message; failures never expose key material."""
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad(sequence))
        payload = json.loads(plaintext.decode("utf-8"))
        if payload["sequence"] != sequence:
            raise ValueError("sequence mismatch")
        return ChatMessage(
            sequence=int(payload["sequence"]),
            sender=str(payload["sender"]),
            body=str(payload["body"]),
            timestamp=str(payload["timestamp"]),
        )
    except Exception as exc:  # noqa: BLE001 - InvalidTag and bad JSON are both expected failures
        raise AuthError("message authentication failed") from exc


class ChatStore:
    """An encrypted local message store. The key lives only in memory."""

    def __init__(self, path: Path, key: bytes | None = None) -> None:
        self.path = Path(path)
        self._key = derive_lab_key() if key is None else key
        self._records: dict[int, StoredRecord] = {}
        if self.path.exists():
            self._load()

    def __repr__(self) -> str:
        # Deliberately excludes the key and any key material.
        return f"ChatStore(path={str(self.path)!r}, messages={len(self._records)})"

    def _load(self) -> None:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StoreFormatError("chat store is missing or invalid JSON") from exc
        if not isinstance(document, dict) or document.get("format") != _FORMAT:
            raise StoreFormatError("unsupported chat store format")
        records = document.get("messages")
        if not isinstance(records, list):
            raise StoreFormatError("chat store messages must be a list")
        loaded: dict[int, StoredRecord] = {}
        for item in records:
            try:
                sequence = int(item["sequence"])
                nonce = _unb64(str(item["nonce"]))
                ciphertext = _unb64(str(item["ciphertext"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise StoreFormatError("malformed chat record") from exc
            if sequence < 1 or len(nonce) != _NONCE_BYTES:
                raise StoreFormatError("malformed chat record")
            if sequence in loaded:
                raise StoreFormatError("duplicate sequence in chat store")
            loaded[sequence] = StoredRecord(sequence, str(item["nonce"]), str(item["ciphertext"]))
        self._records = loaded

    def _write(self) -> None:
        document = {
            "format": _FORMAT,
            "messages": [
                {"sequence": r.sequence, "nonce": r.nonce, "ciphertext": r.ciphertext}
                for r in sorted(self._records.values(), key=lambda record: record.sequence)
            ],
        }
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        os.replace(temp, self.path)

    def create(self) -> None:
        """Create an empty store file."""
        if self.path.exists():
            raise ValueError("chat store already exists")
        self._records = {}
        self._write()

    def append(self, message: ChatMessage, nonce: bytes | None = None) -> StoredRecord:
        """Append one message with a fresh (or caller-supplied lab) nonce."""
        if message.sequence in self._records:
            raise DuplicateSequenceError(f"sequence {message.sequence} already exists")
        chosen = os.urandom(_NONCE_BYTES) if nonce is None else nonce
        ciphertext = encrypt_payload(self._key, chosen, message)
        record = StoredRecord(message.sequence, _b64(chosen), _b64(ciphertext))
        self._records[message.sequence] = record
        self._write()
        return record

    def read(self) -> tuple[ChatMessage, ...]:
        """Read and authenticate every message in sequence order."""
        messages = []
        for record in sorted(self._records.values(), key=lambda item: item.sequence):
            messages.append(decrypt_payload(self._key, _unb64(record.nonce), _unb64(record.ciphertext), record.sequence))
        return tuple(messages)


def _resolve_key(path: Path | None) -> bytes:
    return derive_lab_key() if path is None else load_key_file(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="create an empty encrypted store")
    init_p.add_argument("store", type=Path)
    init_p.add_argument("--key-file", type=Path, help="optional 32-byte hex key file")

    send_p = sub.add_parser("send", help="append one encrypted message")
    send_p.add_argument("store", type=Path)
    send_p.add_argument("sender")
    send_p.add_argument("body")
    send_p.add_argument("--sequence", type=int, required=True)
    send_p.add_argument("--timestamp", required=True, help="caller-supplied timestamp string")
    send_p.add_argument("--key-file", type=Path)

    read_p = sub.add_parser("read", help="read and authenticate all messages")
    read_p.add_argument("store", type=Path)
    read_p.add_argument("--key-file", type=Path)

    keygen_p = sub.add_parser("keygen", help="write a new 32-byte lab key to a file")
    keygen_p.add_argument("path", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            write_key_file(args.path)
            print(f"wrote a new lab key file to {args.path} (keep it private)")
            return 0

        key = _resolve_key(args.key_file)
        if args.command == "init":
            ChatStore(args.store, key).create()
            print(f"created {args.store}")
            return 0

        if args.command == "send":
            store = ChatStore(args.store, key)
            store.append(ChatMessage(args.sequence, args.sender, args.body, args.timestamp))
            print(f"stored message {args.sequence} (ciphertext only)")
            return 0

        if not args.store.exists():
            raise ValueError("chat store does not exist")
        messages = ChatStore(args.store, key).read()
        if not messages:
            print("no messages")
        for message in messages:
            print(f"[{message.sequence}] {message.timestamp} {message.sender}: {message.body}")
        return 0
    except (AuthError, StoreFormatError, DuplicateSequenceError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
