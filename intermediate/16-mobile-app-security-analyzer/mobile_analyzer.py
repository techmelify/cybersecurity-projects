#!/usr/bin/env python3
"""Static analyzer for synthetic Android/iOS manifest snapshots.

Python-only project. It consumes the JSON manifest supplied by the caller and
reports common misconfigurations. It does not parse real APK/IPA archives and
does not talk to a device or an app store.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

__all__ = [
    "Component",
    "Manifest",
    "Finding",
    "analyze",
    "load_manifest",
]

_DANGEROUS_PERMISSIONS = frozenset(
    {
        "READ_SMS",
        "SEND_SMS",
        "WRITE_SMS",
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "ACCESS_FINE_LOCATION",
        "RECORD_AUDIO",
        "CAMERA",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "SYSTEM_ALERT_WINDOW",
        "READ_PHONE_STATE",
    }
)

# Boolean flags whose secure value is False. A missing key is treated as a
# finding, mirroring the "secure by default" expectation of a hardened build.
_SECURE_FLAGS: dict[str, bool] = {
    "allowBackup": False,
    "debuggable": False,
    "cleartextTrafficPermitted": False,
}


@dataclass(frozen=True)
class Component:
    """A synthetic app component such as an activity or service."""

    name: str
    kind: str
    exported: bool = False
    permission: str | None = None


@dataclass(frozen=True)
class Manifest:
    """A simplified, platform-neutral view of an app manifest."""

    platform: str
    package: str
    permissions: tuple[str, ...] = ()
    cleartext_traffic: bool = False
    components: tuple[Component, ...] = ()
    secure_flags: Mapping[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """One misconfiguration reported by :func:`analyze`."""

    severity: str
    category: str
    detail: str


def analyze(manifest: Manifest) -> list[Finding]:
    """Return findings in a stable order: permissions, traffic, components, flags."""
    findings: list[Finding] = []

    for permission in sorted(set(manifest.permissions)):
        if permission in _DANGEROUS_PERMISSIONS:
            findings.append(
                Finding(
                    "high",
                    "excessive-permission",
                    f"{manifest.package} requests {permission}",
                )
            )

    if manifest.cleartext_traffic:
        findings.append(
            Finding(
                "high",
                "cleartext-traffic",
                f"{manifest.package} permits cleartext network traffic",
            )
        )

    for component in manifest.components:
        if component.exported and not component.permission:
            findings.append(
                Finding(
                    "high",
                    "exported-component",
                    f"{component.kind} {component.name} is exported without a permission",
                )
            )

    for flag, expected in sorted(_SECURE_FLAGS.items()):
        actual = manifest.secure_flags.get(flag)
        if actual != expected:
            findings.append(
                Finding(
                    "medium",
                    "missing-secure-flag",
                    f"{flag} should be {expected}, found {actual!r}",
                )
            )
    return findings


def load_manifest(data: Mapping[str, object]) -> Manifest:
    """Parse a JSON manifest mapping into a :class:`Manifest` object."""
    raw_permissions = data.get("permissions", [])
    raw_components = data.get("components", [])
    raw_flags = data.get("secure_flags", {})
    if not isinstance(raw_flags, Mapping):
        raise TypeError("secure_flags must be an object")

    components = tuple(
        Component(
            name=str(item["name"]),
            kind=str(item.get("kind", "activity")),
            exported=bool(item.get("exported", False)),
            permission=(
                None if item.get("permission") is None else str(item["permission"])
            ),
        )
        for item in raw_components
    )
    return Manifest(
        platform=str(data["platform"]),
        package=str(data["package"]),
        permissions=tuple(str(value) for value in raw_permissions),
        cleartext_traffic=bool(data.get("cleartext_traffic", False)),
        components=components,
        secure_flags={str(key): bool(value) for key, value in raw_flags.items()},
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a synthetic mobile manifest for security misconfigurations."
    )
    parser.add_argument("manifest", type=Path, help="JSON manifest snapshot")
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(
            json.loads(args.manifest.read_text(encoding="utf-8"))
        )
        findings = analyze(manifest)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for finding in findings:
        print(
            f"[{finding.severity.upper():6}] {finding.category}: {finding.detail}"
        )
    print(f"{len(findings)} finding(s) for {manifest.package} ({manifest.platform})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
