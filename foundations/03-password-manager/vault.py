#!/usr/bin/env python3
"""Encrypted local password vault.

Argon2id derives a key from the master password; AES-256-GCM encrypts the
serialized entries. The vault file contains no plaintext credentials.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

__all__ = ["Vault", "create_vault", "WrongPassword", "VaultExists"]

_FORMAT = "local-vault-v1"
_AAD = b"local-vault-v1"
_LENGTH = 32
_ITERATIONS = 3
_LANES = 4
_MEMORY_COST = 32768  # KiB (32 MiB)
_SALT_BYTES = 16
_NONCE_BYTES = 12


class WrongPassword(Exception):
    """Raised when the master password cannot decrypt the vault."""


class VaultExists(Exception):
    """Raised when creating a vault that already exists."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _derive(master: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=_LENGTH,
        iterations=_ITERATIONS,
        lanes=_LANES,
        memory_cost=_MEMORY_COST,
    )
    return kdf.derive(master.encode("utf-8"))


def create_vault(path: Path, master: str) -> Vault:
    """Create a new empty vault and return it unlocked."""
    if path.exists():
        raise VaultExists(f"vault already exists: {path}")
    salt = os.urandom(_SALT_BYTES)
    key = _derive(master, salt)
    document = {"format": _FORMAT, "entries": {}, "salt": _b64(salt)}
    vault = Vault(path, master, salt, key, {})
    vault._write()
    return vault


class Vault:
    """An unlocked vault. Call :meth:`unlock` to load an existing file."""

    def __init__(self, path: Path, master: str, salt: bytes, key: bytes, entries: dict[str, Any]):
        self.path = Path(path)
        self._master = master
        self._salt = salt
        self._key = key
        self._entries = entries

    @classmethod
    def unlock(cls, path: Path, master: str) -> Vault:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if raw.get("format") != _FORMAT:
            raise ValueError(f"unsupported vault format: {raw.get('format')!r}")
        salt = _unb64(raw["salt"])
        key = _derive(master, salt)
        nonce = _unb64(raw["nonce"])
        try:
            plaintext = AESGCM(key).decrypt(nonce, _unb64(raw["ciphertext"]), _AAD)
        except Exception as exc:  # noqa: BLE001 - InvalidTag is the expected failure
            raise WrongPassword("master password is incorrect or vault is corrupt") from exc
        entries = json.loads(plaintext.decode("utf-8"))
        return cls(path, master, salt, key, entries)

    def _write(self) -> None:
        nonce = os.urandom(_NONCE_BYTES)
        plaintext = json.dumps(self._entries, sort_keys=True).encode("utf-8")
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, _AAD)
        document = {
            "format": _FORMAT,
            "salt": _b64(self._salt),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
        }
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        os.replace(temp, self.path)

    def add(self, service: str, username: str, password: str) -> None:
        key = service.lower()
        existing = self._entries.get(key, {})
        existing[username] = password
        self._entries[key] = existing
        self._write()

    def get(self, service: str, username: str | None = None) -> dict[str, str]:
        entries = self._entries.get(service.lower(), {})
        if not entries:
            raise KeyError(service)
        if username is not None:
            if username not in entries:
                raise KeyError(username)
            return {username: entries[username]}
        return dict(entries)

    def list_services(self) -> dict[str, list[str]]:
        return {name: sorted(users) for name, users in sorted(self._entries.items())}

    def delete(self, service: str, username: str | None = None) -> None:
        key = service.lower()
        if key not in self._entries:
            raise KeyError(service)
        if username is None:
            del self._entries[key]
        else:
            if username not in self._entries[key]:
                raise KeyError(username)
            del self._entries[key][username]
            if not self._entries[key]:
                del self._entries[key]
        self._write()


def _read_master(confirm: bool = False) -> str:
    master = getpass.getpass("Master password: ")
    if confirm and master != getpass.getpass("Confirm: "):
        raise ValueError("passwords do not match")
    return master


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Encrypted local password vault.")
    parser.add_argument("vault", type=Path, help="path to the vault file")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create an empty vault")
    add_p = sub.add_parser("add", help="store a credential")
    add_p.add_argument("service")
    add_p.add_argument("username")
    add_p.add_argument("password")
    sub.add_parser("list", help="list services and usernames")
    get_p = sub.add_parser("get", help="read a credential")
    get_p.add_argument("service")
    get_p.add_argument("username", nargs="?")
    del_p = sub.add_parser("delete", help="remove a credential or service")
    del_p.add_argument("service")
    del_p.add_argument("username", nargs="?")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            create_vault(args.vault, _read_master(confirm=True))
            print(f"created {args.vault}")
            return 0

        master = _read_master()
        vault = Vault.unlock(args.vault, master)
        if args.command == "add":
            vault.add(args.service, args.username, args.password)
            print("stored")
        elif args.command == "list":
            for service, users in vault.list_services().items():
                print(f"{service}: {', '.join(users)}")
        elif args.command == "get":
            for user, password in vault.get(args.service, args.username).items():
                print(f"{user}: {password}")
        elif args.command == "delete":
            vault.delete(args.service, args.username)
            print("deleted")
        return 0
    except (WrongPassword, VaultExists, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
