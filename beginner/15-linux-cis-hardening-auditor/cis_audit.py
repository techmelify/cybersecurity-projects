#!/usr/bin/env python3
"""Read-only Linux hardening auditor driven by a synthetic file snapshot.

Checks a small CIS-inspired subset. It never edits a system and reads live
files only if you explicitly pass real paths in a JSON snapshot.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

__all__ = ["Check", "audit", "parse_sshd_config"]


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    status: str  # pass | warn | fail
    detail: str


def parse_sshd_config(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower()] = parts[1].strip()
    return result


def audit(
    files: Mapping[str, str],
    modes: Mapping[str, int] | None = None,
) -> list[Check]:
    modes = modes or {}
    checks: list[Check] = []

    sshd = parse_sshd_config(files.get("/etc/ssh/sshd_config", ""))
    root_login = sshd.get("permitrootlogin", "")
    checks.append(
        Check("SSH-01", "Root login disabled", "pass" if root_login.lower() == "no" else "fail", f"PermitRootLogin={root_login or 'unset'}")
    )
    password_auth = sshd.get("passwordauthentication", "")
    checks.append(
        Check("SSH-02", "Password authentication disabled", "pass" if password_auth.lower() == "no" else "warn", f"PasswordAuthentication={password_auth or 'unset'}")
    )

    shadow_mode = modes.get("/etc/shadow")
    if shadow_mode is None:
        checks.append(Check("AUTH-01", "Shadow file permissions", "warn", "no stat data"))
    else:
        ok = shadow_mode & 0o077 == 0
        checks.append(Check("AUTH-01", "Shadow file permissions", "pass" if ok else "fail", f"mode={shadow_mode:04o}"))

    passwd_mode = modes.get("/etc/passwd")
    if passwd_mode is None:
        checks.append(Check("AUTH-02", "Passwd file permissions", "warn", "no stat data"))
    else:
        ok = passwd_mode & 0o022 == 0
        checks.append(Check("AUTH-02", "Passwd file permissions", "pass" if ok else "fail", f"mode={passwd_mode:04o}"))

    limits = files.get("/etc/security/limits.conf", "")
    core_disabled = any(line.strip().startswith("* hard core 0") for line in limits.splitlines())
    checks.append(Check("KERN-01", "Core dumps disabled", "pass" if core_disabled else "warn", "hard core limit"))

    sysctl = files.get("/etc/sysctl.conf", "")
    ip_forward = any(line.strip().replace(" ", "") == "net.ipv4.ip_forward=0" for line in sysctl.splitlines())
    checks.append(Check("NET-01", "IP forwarding disabled", "pass" if ip_forward else "warn", "net.ipv4.ip_forward"))

    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a JSON file snapshot for CIS-style hardening.")
    parser.add_argument("snapshot", type=Path, help='JSON: {"files": {...}, "modes": {...}}')
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        checks = audit(data.get("files", {}), data.get("modes", {}))
    except (OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for check in checks:
        print(f"[{check.status.upper():4}] {check.id} {check.title}: {check.detail}")
    passed = sum(c.status == "pass" for c in checks)
    print(f"{passed}/{len(checks)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
