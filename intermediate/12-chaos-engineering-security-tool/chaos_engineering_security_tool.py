#!/usr/bin/env python3
"""Plan and *simulate* security-focused fault scenarios.

The tool parses a JSON or YAML-like manifest, computes blast radius and risk,
and emits a timeline of simulated events plus rollback steps. It deliberately
has no execution layer: no subprocess, no sockets, no service calls. Nothing
is ever disrupted.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

__all__ = [
    "BlastRadius",
    "Scenario",
    "SimulationEvent",
    "SimulationReport",
    "SimulationConfig",
    "load_manifest",
    "build_plan",
    "simulate",
    "main",
]

_KNOWN_FAULTS = frozenset(
    {
        "auth_delay",
        "tls_config_regression",
        "firewall_rule_misconfiguration",
        "token_expiry_skew",
        "rate_limit_disabled",
        "logging_drop",
    }
)
_FAULT_RISK = {
    "auth_delay": 5,
    "tls_config_regression": 8,
    "firewall_rule_misconfiguration": 9,
    "token_expiry_skew": 6,
    "rate_limit_disabled": 6,
    "logging_drop": 7,
}
_SENSITIVITY_WEIGHT = {"low": 0, "medium": 10, "high": 20}
_MAPPING_ENTRY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:")
_TOKEN = re.compile(r"[A-Za-z0-9_./@+\-]+")


@dataclass(frozen=True)
class BlastRadius:
    """Declared scope of a scenario."""

    services: tuple[str, ...] = ()
    users: int = 0
    regions: tuple[str, ...] = ()
    data_sensitivity: str = "low"


@dataclass(frozen=True)
class Scenario:
    """One planned, security-focused fault scenario."""

    id: str
    target: str
    fault: str
    title: str
    duration_seconds: int
    blast_radius: BlastRadius
    rollback: tuple[str, ...]
    enabled: bool = True


@dataclass(frozen=True)
class SimulationEvent:
    """A timeline entry describing a simulated phase."""

    scenario_id: str
    phase: str
    message: str


@dataclass(frozen=True)
class SimulationConfig:
    """Risk-budget settings for simulation."""

    max_risk_score: int = 70
    include_verification: bool = True


@dataclass(frozen=True)
class SimulationReport:
    """Complete simulation output, with no execution results."""

    scenarios: tuple[Scenario, ...]
    events: tuple[SimulationEvent, ...]
    risk_scores: dict[str, int]
    rollback_plan: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def max_risk(self) -> int:
        return max(self.risk_scores.values(), default=0)


# ---------------------------------------------------------------------------
# Minimal JSON / YAML-like manifest reader (standard library only)
# ---------------------------------------------------------------------------


def _strip_comments(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        quote: str | None = None
        escaped = False
        kept: list[str] = []
        for index, char in enumerate(line):
            if quote is not None:
                kept.append(char)
                if quote == '"' and char == "\\" and not escaped:
                    escaped = True
                    continue
                if char == quote and not escaped:
                    quote = None
                escaped = False
            elif char in ('"', "'"):
                quote = char
                kept.append(char)
            elif char == "#" and (index == 0 or line[index - 1].isspace()):
                break
            else:
                kept.append(char)
        lines.append("".join(kept))
    return "\n".join(lines)


def _is_number(token: str) -> bool:
    return bool(re.fullmatch(r"-?\d+(?:\.\d+)?", token))


def _quote_bare_tokens(text: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in ('"', "'"):
            end = text.find(char, index + 1)
            if end < 0:
                raise ValueError("unterminated quoted value in inline collection")
            output.append(json.dumps(text[index + 1 : end]))
            index = end + 1
            continue
        match = _TOKEN.match(text, index)
        if match:
            token = match.group(0)
            if token.lower() in {"true", "false", "null"} or _is_number(token):
                output.append(token)
            else:
                output.append(json.dumps(token))
            index = match.end()
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _scalar(value: str) -> Any:
    text = value.strip()
    if not text:
        return None
    if text[0] in "[{":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return json.loads(_quote_bare_tokens(text))
    if text[0] == '"':
        return json.loads(text)
    if text[0] == "'" and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    lowered = text.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "~"}:
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if _is_number(text):
        return float(text)
    return text


def _yamlish_lines(text: str) -> list[list[Any]]:
    lines: list[list[Any]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        indent = len(raw) - len(raw.lstrip(" "))
        if "\t" in raw[:indent]:
            raise ValueError(f"line {number}: tabs are not valid indentation")
        stripped = raw.strip()
        if not stripped:
            continue
        lines.append([indent, stripped, number])
    return lines


def _is_list_item(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _is_mapping_entry(content: str) -> bool:
    return bool(_MAPPING_ENTRY.match(content))


def _parse_block(lines: list[list[Any]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        raise ValueError("unexpected end of manifest")
    if lines[index][0] < indent:
        raise ValueError(f"line {lines[index][2]}: unexpected indentation")
    if _is_list_item(lines[index][1]):
        return _parse_list(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_mapping(lines: list[list[Any]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines) and lines[index][0] == indent and not _is_list_item(lines[index][1]):
        line_indent, content, number = lines[index]
        if ":" not in content:
            raise ValueError(f"line {number}: expected 'key: value'")
        key, _, value = content.partition(":")
        key = key.strip()
        if not key:
            raise ValueError(f"line {number}: empty key")
        index += 1
        value = value.strip()
        if value:
            result[key] = _scalar(value)
        elif index < len(lines) and lines[index][0] > line_indent:
            child, index = _parse_block(lines, index, lines[index][0])
            result[key] = child
        else:
            result[key] = None
    return result, index


def _parse_list(lines: list[list[Any]], index: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines) and lines[index][0] == indent and _is_list_item(lines[index][1]):
        number = lines[index][2]
        content = lines[index][1][1:].strip()
        index += 1
        if content and _is_mapping_entry(content):
            # Turn "- key: value" into a list item whose child is a mapping.
            lines.insert(index, [indent + 2, content, number])
            content = ""
        if content:
            items.append(_scalar(content))
        elif index < len(lines) and lines[index][0] > indent:
            child, index = _parse_block(lines, index, lines[index][0])
            items.append(child)
        else:
            items.append(None)
    return items, index


def load_manifest(text: str) -> dict[str, Any]:
    """Load a JSON manifest, or the small YAML-like subset used in examples."""

    cleaned = _strip_comments(text)
    try:
        document = json.loads(cleaned)
    except json.JSONDecodeError:
        lines = _yamlish_lines(cleaned)
        if not lines:
            raise ValueError("empty manifest") from None
        document, index = _parse_block(lines, 0, lines[0][0])
        if index != len(lines):
            raise ValueError(f"line {lines[index][2]}: unexpected indentation")
    if not isinstance(document, dict):
        raise ValueError("manifest root must be a mapping")
    return document


# ---------------------------------------------------------------------------
# Planning and simulation
# ---------------------------------------------------------------------------


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"false", "no", "off", "0", ""}
    return bool(value)


def _blast_radius(raw: Any) -> BlastRadius:
    data = _as_mapping(raw)
    sensitivity = str(data.get("data_sensitivity", "low")).lower()
    if sensitivity not in _SENSITIVITY_WEIGHT:
        raise ValueError(f"unsupported data_sensitivity '{sensitivity}'")
    try:
        users = int(data.get("users", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("blast_radius.users must be an integer") from exc
    return BlastRadius(
        tuple(str(item) for item in _as_list(data.get("services"))),
        users,
        tuple(str(item) for item in _as_list(data.get("regions"))),
        sensitivity,
    )


def build_plan(manifest: Mapping[str, Any]) -> tuple[Scenario, ...]:
    """Validate a manifest and return immutable scenario records."""

    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    raw_scenarios = manifest.get("scenarios")
    if not isinstance(raw_scenarios, list):
        raise ValueError("manifest.scenarios must be a list")

    scenarios: list[Scenario] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_scenarios):
        data = _as_mapping(raw)
        if not data:
            raise ValueError(f"scenario {index} must be a mapping")
        identifier = str(data.get("id", "")).strip()
        target = str(data.get("target", "")).strip()
        fault = str(data.get("fault", "")).strip().lower()
        if not identifier or identifier in seen:
            raise ValueError(f"scenario {index} needs a unique id")
        if not target:
            raise ValueError(f"scenario '{identifier}' needs a target")
        if fault not in _KNOWN_FAULTS:
            raise ValueError(f"scenario '{identifier}' has unsupported fault '{fault}'")
        seen.add(identifier)
        try:
            duration = int(data.get("duration_seconds", 60))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"scenario '{identifier}' has invalid duration_seconds") from exc
        if duration < 0:
            raise ValueError(f"scenario '{identifier}' has negative duration_seconds")
        scenarios.append(
            Scenario(
                identifier,
                target,
                fault,
                str(data.get("title", identifier)),
                duration,
                _blast_radius(data.get("blast_radius")),
                tuple(str(step) for step in _as_list(data.get("rollback"))),
                _as_bool(data.get("enabled", True)),
            )
        )
    return tuple(scenarios)


def _risk_score(scenario: Scenario) -> int:
    radius = scenario.blast_radius
    score = _FAULT_RISK[scenario.fault] * 5
    score += min(len(radius.services), 10) * 2
    score += min(radius.users, 1000) // 10
    score += _SENSITIVITY_WEIGHT[radius.data_sensitivity]
    score += min(scenario.duration_seconds // 60, 10)
    return min(score, 100)


def simulate(
    scenarios: Sequence[Scenario], config: SimulationConfig | None = None
) -> SimulationReport:
    """Produce a simulated timeline, risk scores, and rollback plan."""

    settings = config or SimulationConfig()
    events: list[SimulationEvent] = []
    scores: dict[str, int] = {}
    rollback: list[str] = []
    warnings: list[str] = []

    for scenario in scenarios:
        if not scenario.enabled:
            events.append(SimulationEvent(scenario.id, "plan", "scenario disabled; skipped"))
            continue

        score = _risk_score(scenario)
        scores[scenario.id] = score
        radius = scenario.blast_radius
        events.append(
            SimulationEvent(
                scenario.id,
                "plan",
                f"planned {scenario.fault} on {scenario.target} for {scenario.duration_seconds}s",
            )
        )
        if not scenario.rollback:
            events.append(
                SimulationEvent(scenario.id, "plan", "warning: no rollback steps declared")
            )
        events.append(
            SimulationEvent(
                scenario.id,
                "simulate",
                f"simulated {scenario.fault}; no disruption was executed",
            )
        )
        if settings.include_verification:
            events.append(
                SimulationEvent(
                    scenario.id,
                    "verify",
                    f"blast radius: {len(radius.services)} service(s), {radius.users} user(s), "
                    f"{radius.data_sensitivity} data",
                )
            )
        for step in scenario.rollback:
            events.append(SimulationEvent(scenario.id, "rollback", f"rollback step: {step}"))
            rollback.append(f"{scenario.id}: {step}")
        if score > settings.max_risk_score:
            warnings.append(f"{scenario.id}: risk {score} exceeds budget {settings.max_risk_score}")

    return SimulationReport(
        tuple(scenarios), tuple(events), scores, tuple(rollback), tuple(warnings)
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan and simulate security fault scenarios (no disruption executed)."
    )
    parser.add_argument("manifest", help="local JSON or YAML-like manifest")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument("--max-risk", type=int, default=SimulationConfig.max_risk_score)
    args = parser.parse_args(argv)

    from pathlib import Path

    try:
        manifest = load_manifest(Path(args.manifest).read_text(encoding="utf-8"))
        scenarios = build_plan(manifest)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(f"cannot load plan: {exc}")
        return 2

    report = simulate(scenarios, SimulationConfig(max_risk_score=args.max_risk))
    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        for scenario in report.scenarios:
            score = report.risk_scores.get(scenario.id)
            state = "enabled" if scenario.enabled else "disabled"
            print(f"{scenario.id}: {scenario.fault} on {scenario.target} [{state}] risk={score}")
        for warning in report.warnings:
            print(f"WARNING {warning}")
        print(f"{len(report.events)} simulated event(s), {len(report.rollback_plan)} rollback step(s)")
    return 1 if report.warnings else 0


if __name__ == "__main__":
    sys.exit(main())
