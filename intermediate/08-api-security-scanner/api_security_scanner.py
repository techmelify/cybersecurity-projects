#!/usr/bin/env python3
"""Static checks for an OpenAPI-like JSON specification.

This is a CLI-only, offline scanner: it reads a local JSON document and never
issues an HTTP request. All findings come from the supplied structure.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Any, Iterator, Mapping, Sequence

__all__ = ["ScanConfig", "ApiFinding", "ApiReport", "analyze_spec", "main"]

_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class ScanConfig:
    """Tunable policy for the specification checks."""

    write_methods: tuple[str, ...] = ("post", "put", "patch", "delete")
    rate_limit_keywords: tuple[str, ...] = ("rate limit", "rate-limit", "throttl")
    verbose_error_markers: tuple[str, ...] = (
        "traceback",
        "stack trace",
        "debug mode",
        "internal path",
        "/usr/src/app",
    )


@dataclass(frozen=True)
class ApiFinding:
    """One policy violation."""

    rule: str
    severity: str
    path: str
    method: str
    message: str

    @property
    def location(self) -> str:
        return f"{self.path} [{self.method}]" if self.method else self.path

    @property
    def message_line(self) -> str:
        return f"{self.rule} ({self.severity}) {self.location}: {self.message}"


@dataclass(frozen=True)
class ApiReport:
    """All findings for one specification."""

    findings: tuple[ApiFinding, ...]
    operations_scanned: int
    scheme_count: int

    @property
    def ok(self) -> bool:
        return not self.findings

    def at_or_above(self, severity: str) -> tuple[ApiFinding, ...]:
        minimum = _SEVERITY_RANK[severity]
        return tuple(f for f in self.findings if _SEVERITY_RANK[f.severity] >= minimum)


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _iter_operations(spec: Mapping[str, Any]) -> Iterator[tuple[str, str, Mapping[str, Any]]]:
    for path, path_item in sorted(_as_mapping(spec.get("paths")).items()):
        for method, operation in sorted(_as_mapping(path_item).items()):
            if method.lower() in _HTTP_METHODS and isinstance(operation, Mapping):
                yield str(path), method.lower(), operation


def _security_schemes(spec: Mapping[str, Any]) -> Mapping[str, Any]:
    components = _as_mapping(spec.get("components"))
    schemes = components.get("securitySchemes")
    if schemes is None:
        schemes = spec.get("securityDefinitions")  # Swagger 2 style
    return _as_mapping(schemes)


def _effective_security(spec: Mapping[str, Any], operation: Mapping[str, Any]) -> list[Any]:
    security = operation.get("security") if "security" in operation else spec.get("security")
    return list(security) if isinstance(security, list) else []


def _is_anonymous(security: list[Any]) -> bool:
    if not security:
        return True
    return any(not isinstance(entry, Mapping) or not entry for entry in security)


def _security_names(security: list[Any]) -> set[str]:
    names: set[str] = set()
    for entry in security:
        if isinstance(entry, Mapping):
            names.update(str(name) for name in entry)
    return names


def _is_weak_scheme(name: str, definition: Mapping[str, Any]) -> str | None:
    scheme_type = str(definition.get("type", "")).lower()
    scheme = str(definition.get("scheme", "")).lower()
    location = str(definition.get("in", "")).lower()

    if scheme_type == "http" and scheme in {"basic", "digest"}:
        return "uses reversible HTTP basic/digest credentials"
    if scheme_type == "http" and not scheme:
        return "HTTP scheme is not declared"
    if scheme_type == "apikey" and location == "query":
        return "API key is transported in the query string"
    if scheme_type == "oauth2":
        flows = _as_mapping(definition.get("flows"))
        if "implicit" in flows:
            return "OAuth2 implicit flow is deprecated"
    return None


def _has_rate_limit(
    spec: Mapping[str, Any], operation: Mapping[str, Any], config: ScanConfig
) -> bool:
    if spec.get("x-rate-limit") or operation.get("x-rate-limit"):
        return True
    responses = _as_mapping(operation.get("responses"))
    if "429" in responses:
        return True
    prose = " ".join(
        str(operation.get(field, "")) for field in ("summary", "description")
    ).lower()
    return any(keyword in prose for keyword in config.rate_limit_keywords)


def _verbose_error_responses(operation: Mapping[str, Any], config: ScanConfig) -> list[str]:
    hits: list[str] = []
    for code, response in sorted(_as_mapping(operation.get("responses")).items()):
        payload = json.dumps(response, default=str).lower()
        if any(marker in payload for marker in config.verbose_error_markers):
            hits.append(str(code))
    return hits


def analyze_spec(spec: Mapping[str, Any], config: ScanConfig | None = None) -> ApiReport:
    """Run all static checks against an OpenAPI-like mapping."""

    settings = config or ScanConfig()
    if not isinstance(spec, Mapping):
        raise TypeError("spec must be a mapping")
    paths = spec.get("paths")
    if paths is not None and not isinstance(paths, Mapping):
        raise ValueError("spec.paths must be a mapping")

    schemes = _security_schemes(spec)
    findings: list[ApiFinding] = []

    if paths and not schemes:
        findings.append(
            ApiFinding(
                "SEC001",
                "high",
                "<root>",
                "",
                "operations are defined but no security scheme is declared",
            )
        )

    for name, definition in sorted(schemes.items()):
        reason = _is_weak_scheme(name, _as_mapping(definition))
        if reason:
            findings.append(ApiFinding("SEC003", "medium", "<components>", "", f"scheme '{name}' {reason}"))

    declared_names = set(schemes)
    operations = list(_iter_operations(spec))
    write_methods = {method.lower() for method in settings.write_methods}

    for path, method, operation in operations:
        security = _effective_security(spec, operation)

        for name in sorted(_security_names(security) - declared_names):
            findings.append(
                ApiFinding("SEC002", "high", path, method, f"undefined security scheme '{name}'")
            )

        if method in write_methods and _is_anonymous(security):
            findings.append(
                ApiFinding("SEC005", "high", path, method, "write operation has no effective authentication")
            )

        if not _has_rate_limit(spec, operation, settings):
            findings.append(
                ApiFinding("SEC006", "low", path, method, "no rate-limit description or 429 response")
            )

        for code in _verbose_error_responses(operation, settings):
            findings.append(
                ApiFinding("SEC004", "medium", path, method, f"response {code} exposes verbose error details")
            )

    findings.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.rule, f.path, f.method))
    return ApiReport(tuple(findings), len(operations), len(schemes))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Statically audit an OpenAPI-like JSON spec.")
    parser.add_argument("spec", help="path to a local JSON specification")
    parser.add_argument("--json", action="store_true", help="emit JSON findings")
    parser.add_argument("--strict", action="store_true", help="exit 1 when any finding exists")
    args = parser.parse_args(argv)

    from pathlib import Path

    try:
        document = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"cannot read specification: {exc}")
        return 2

    try:
        report = analyze_spec(document)
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))
        return 2

    if args.json:
        print(json.dumps([asdict(f) for f in report.findings], indent=2))
    else:
        for finding in report.findings:
            print(finding.message_line)
        print(
            f"{len(report.findings)} finding(s) across {report.operations_scanned} operation(s), "
            f"{report.scheme_count} scheme(s)"
        )
    return 1 if args.strict and report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
