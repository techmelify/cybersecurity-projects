#!/usr/bin/env python3
"""Generate and track canary tokens in a local JSON registry.

Tokens are random with an HMAC signature. The registry stores only a SHA-256
digest of each token, never the token itself.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["CanaryRegistry", "CanaryToken", "InvalidToken"]


class InvalidToken(Exception):
    """Raised when a token is malformed or has a bad signature."""


@dataclass(frozen=True)
class CanaryToken:
    value: str
    token_id: str

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.value.encode("ascii")).hexdigest()


class CanaryRegistry:
    def __init__(self, path: Path, secret: bytes):
        self.path = Path(path)
        self._secret = secret
        self._data: dict[str, Any] = {"tokens": {}}

    @classmethod
    def create(cls, path: Path) -> "CanaryRegistry":
        path = Path(path)
        if path.exists():
            raise FileExistsError(f"registry already exists: {path}")
        secret = secrets.token_bytes(32)
        registry = cls(path, secret)
        registry._data["secret"] = secret.hex()
        registry._save()
        return registry

    @classmethod
    def load(cls, path: Path) -> "CanaryRegistry":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        registry = cls(path, bytes.fromhex(data["secret"]))
        registry._data = data
        return registry

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def issue(self, note: str = "") -> CanaryToken:
        payload = secrets.token_urlsafe(18)
        signature = hmac.new(self._secret, payload.encode("ascii"), hashlib.sha256).hexdigest()[:32]
        value = f"ct1_{payload}.{signature}"
        token_id = hashlib.sha256(value.encode("ascii")).hexdigest()[:12]
        self._data["tokens"][hashlib.sha256(value.encode("ascii")).hexdigest()] = {
            "id": token_id,
            "note": note,
            "created": time.time(),
            "hits": [],
        }
        self._save()
        return CanaryToken(value, token_id)

    @staticmethod
    def _payload_and_signature(value: str) -> tuple[str, str]:
        if not value.startswith("ct1_") or "." not in value:
            raise InvalidToken("malformed canary token")
        body, signature = value[4:].rsplit(".", 1)
        return body, signature

    def verify(self, value: str) -> dict[str, Any] | None:
        payload, signature = self._payload_and_signature(value)
        expected = hmac.new(self._secret, payload.encode("ascii"), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(signature, expected):
            return None
        digest = hashlib.sha256(value.encode("ascii")).hexdigest()
        return self._data["tokens"].get(digest)

    def record_hit(self, value: str, source: str = "unknown", user_agent: str = "") -> dict[str, Any]:
        record = self.verify(value)
        if record is None:
            raise InvalidToken("unknown or invalid token")
        record["hits"].append({"time": time.time(), "source": source, "user_agent": user_agent})
        self._save()
        return record

    def list(self) -> list[dict[str, Any]]:
        return [
            {"id": r["id"], "note": r["note"], "hits": len(r["hits"])}
            for r in sorted(self._data["tokens"].values(), key=lambda r: r["created"])
        ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local canary token generator and tracker.")
    parser.add_argument("registry", type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create a new registry")
    issue = sub.add_parser("issue", help="generate a token")
    issue.add_argument("--note", default="")
    verify = sub.add_parser("verify", help="check a token")
    verify.add_argument("token")
    hit = sub.add_parser("hit", help="record a simulated hit")
    hit.add_argument("token")
    hit.add_argument("--source", default="lab")
    sub.add_parser("list", help="list issued tokens")

    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            registry = CanaryRegistry.create(args.registry)
            print(f"created {registry.path}")
            return 0
        registry = CanaryRegistry.load(args.registry)
        if args.command == "issue":
            token = registry.issue(args.note)
            print(token.value)
        elif args.command == "verify":
            print("valid" if registry.verify(args.token) else "invalid")
        elif args.command == "hit":
            record = registry.record_hit(args.token, args.source)
            print(f"recorded hit for {record['id']}")
        elif args.command == "list":
            for item in registry.list():
                print(f"{item['id']}  hits={item['hits']}  {item['note']}")
        return 0
    except (InvalidToken, FileNotFoundError, FileExistsError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
