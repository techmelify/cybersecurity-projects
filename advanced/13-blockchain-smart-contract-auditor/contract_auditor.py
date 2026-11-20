#!/usr/bin/env python3
"""Offline static analyzer for synthetic Solidity source text.

The analyzer looks for four well-known contract pitfalls: reentrancy-prone
ordering, tx.origin authentication, unchecked low-level calls, and privileged
functions without access control. It reads text only: no compiler, chain,
wallet, network, or bytecode execution is involved.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "Finding",
    "FunctionBlock",
    "AuditReport",
    "audit_contract",
    "load_source",
]

_PRIVILEGED_NAMES = frozenset(
    {
        "withdraw",
        "withdrawall",
        "sweep",
        "mint",
        "burn",
        "setowner",
        "transferownership",
        "setadmin",
        "pause",
        "unpause",
        "selfdestruct",
        "upgrade",
        "upgradeto",
        "setfee",
        "setprice",
    }
)
_ACCESS_MODIFIERS = ("onlyowner", "onlyadmin", "onlyrole", "onlyauthorised", "onlyauthorized")
_ACCESS_CHECKS = re.compile(
    r"require\s*\(\s*msg\.sender\s*==\s*(?:owner|admin)\b|_checkowner\s*\(",
    re.IGNORECASE,
)
_CALL_RE = re.compile(r"\.(?:call|send|transfer|delegatecall)\s*(?:\{[^}]*\})?\s*\(")
_STATE_WRITE_RE = re.compile(
    r"\b(?:balances|credits|allowances|amounts|pending)\b\s*\[[^\]]*\]\s*=[^=]"
    r"|\b(?:balances|totalSupply|owner|admin|paused)\s*=[^=]"
)
_TX_ORIGIN_RE = re.compile(r"\btx\.origin\b", re.IGNORECASE)
_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class Finding:
    """A single rule hit with a stable 1-based source line."""

    rule: str
    severity: str
    line: int
    message: str


@dataclass(frozen=True)
class FunctionBlock:
    """One function extracted from the masked source text."""

    name: str
    header: str
    body: str
    start_line: int
    end_line: int
    brace: int = -1


@dataclass(frozen=True)
class AuditReport:
    """Ordered findings plus a small audit summary."""

    findings: tuple[Finding, ...]
    functions_scanned: int

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.rule] = counts.get(finding.rule, 0) + 1
        return counts


def _mask_non_code(source: str) -> str:
    """Blank comments and string literals while preserving every newline.

    Equal-length masking keeps line numbers accurate and stops rule patterns
    from firing on documentation or string contents.
    """
    chars = list(source)
    state = ""
    index = 0
    limit = len(chars)
    while index < limit:
        char = chars[index]
        following = chars[index + 1] if index + 1 < limit else ""
        if state == "":
            if char == "/" and following == "/":
                state = "line"
                chars[index] = chars[index + 1] = " "
                index += 2
                continue
            if char == "/" and following == "*":
                state = "block"
                chars[index] = chars[index + 1] = " "
                index += 2
                continue
            if char in ('"', "'"):
                state = "string"
                chars[index] = " "
                index += 1
                continue
        elif state == "line":
            if char == "\n":
                state = ""
            else:
                chars[index] = " "
        elif state == "block":
            if char == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = ""
                continue
            if char != "\n":
                chars[index] = " "
        elif state == "string":
            if char == "\\":
                chars[index] = " "
                if index + 1 < limit and chars[index + 1] != "\n":
                    chars[index + 1] = " "
                index += 2
                continue
            if char in ('"', "'"):
                state = ""
            chars[index] = " "
        index += 1
    return "".join(chars)


def _matching_index(text: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(text)):
        if text[index] == opening:
            depth += 1
        elif text[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _extract_functions(masked: str) -> list[FunctionBlock]:
    blocks: list[FunctionBlock] = []
    for match in _FUNCTION_RE.finditer(masked):
        close_paren = _matching_index(masked, match.end() - 1, "(", ")")
        if close_paren < 0:
            continue
        brace = masked.find("{", close_paren + 1)
        if brace < 0:
            continue
        end_brace = _matching_index(masked, brace, "{", "}")
        if end_brace < 0:
            continue
        blocks.append(
            FunctionBlock(
                name=match.group(1),
                header=masked[match.start() : brace].strip(),
                body=masked[brace + 1 : end_brace],
                start_line=masked.count("\n", 0, match.start()) + 1,
                end_line=masked.count("\n", 0, end_brace) + 1,
                brace=brace,
            )
        )
    return blocks


def _body_line_number(masked: str, brace: int, index: int) -> int:
    return masked.count("\n", 0, brace + 1) + 1 + index


def _call_is_checked(lines: list[str], index: int) -> bool:
    window = "\n".join(lines[max(0, index - 1) : index + 2])
    if re.search(r"require\s*\(", window):
        return True
    if re.search(r"\(\s*bool\s+\w+\s*,|\bbool\s+\w+\s*=\s*[^;\n]*\.(?:call|send|delegatecall)", window):
        return True
    if re.search(r"\b(?:if\s*\(\s*!\s*\w+\s*\)|revert\s)", window):
        return True
    return False


def _audit_function(block: FunctionBlock, masked: str, brace: int) -> list[Finding]:
    findings: list[Finding] = []
    lines = block.body.splitlines()

    call_indices = [index for index, line in enumerate(lines) if _CALL_RE.search(line)]
    write_indices = [index for index, line in enumerate(lines) if _STATE_WRITE_RE.search(line)]
    if call_indices and write_indices:
        first_call = call_indices[0]
        if any(write > first_call for write in write_indices):
            findings.append(
                Finding(
                    "reentrancy",
                    "high",
                    _body_line_number(masked, brace, first_call),
                    "external call precedes a state update in " + block.name + "()",
                )
            )

    for index, line in enumerate(lines):
        if _TX_ORIGIN_RE.search(line):
            findings.append(
                Finding(
                    "tx-origin-auth",
                    "high",
                    _body_line_number(masked, brace, index),
                    "tx.origin used for identity or authorisation",
                )
            )
        if _CALL_RE.search(line) and not _call_is_checked(lines, index):
            findings.append(
                Finding(
                    "unchecked-low-level-call",
                    "medium",
                    _body_line_number(masked, brace, index),
                    "low-level call result is not checked",
                )
            )

    header = block.header.lower()
    if block.name.lower() in _PRIVILEGED_NAMES:
        has_modifier = any(token in header for token in _ACCESS_MODIFIERS)
        if not has_modifier and not _ACCESS_CHECKS.search(block.body):
            findings.append(
                Finding(
                    "missing-access-control",
                    "high",
                    block.start_line,
                    "privileged function " + block.name + "() has no owner check",
                )
            )
    return findings


def audit_contract(source: str) -> AuditReport:
    """Statically audit Solidity-flavoured source text. Pure and offline."""
    masked = _mask_non_code(source)
    blocks = _extract_functions(masked)
    findings: list[Finding] = []
    for block in blocks:
        findings.extend(_audit_function(block, masked, block.brace))
    ordered = tuple(sorted(findings, key=lambda item: (item.line, item.rule, item.message)))
    return AuditReport(findings=ordered, functions_scanned=len(blocks))


def load_source(text: str | None, file: Path | None) -> str:
    """Return source text from exactly one of a literal or a file path."""
    if text is None and file is None:
        raise ValueError("provide source text or --file")
    if text is not None and file is not None:
        raise ValueError("provide either source text or --file, not both")
    if file is not None:
        return file.read_text(encoding="utf-8")
    assert text is not None
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit synthetic Solidity source text.")
    parser.add_argument("source", nargs="?", help="Solidity source text")
    parser.add_argument("--file", type=Path, help="read Solidity source from a file")
    args = parser.parse_args(argv)
    try:
        source = load_source(args.source, args.file)
    except ValueError as error:
        parser.error(str(error))
    report = audit_contract(source)
    payload = asdict(report)
    payload["clean"] = report.clean
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
