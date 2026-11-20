import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contract_auditor import (  # noqa: E402
    audit_contract,
    load_source,
    main,
)


CLEAN = """
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    function withdraw() public onlyOwner {
        require(balances[msg.sender] > 0, "none");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
    }
}
"""

REENTRANT = """
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() public onlyOwner {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
        require(ok, "failed");
    }
}
"""


class ContractAuditorTests(unittest.TestCase):
    def test_clean_contract(self):
        report = audit_contract(CLEAN)
        self.assertEqual(report.functions_scanned, 2)
        self.assertTrue(report.clean)
        self.assertEqual(report.counts, {})

    def test_reentrancy(self):
        report = audit_contract(REENTRANT)
        rules = {finding.rule for finding in report.findings}
        self.assertIn("reentrancy", rules)
        reentrancy = next(f for f in report.findings if f.rule == "reentrancy")
        self.assertEqual(reentrancy.severity, "high")
        self.assertGreater(reentrancy.line, 0)

    def test_tx_origin_auth(self):
        source = "contract C { function check() public { require(tx.origin == owner); } }"
        report = audit_contract(source)
        self.assertIn("tx-origin-auth", {f.rule for f in report.findings})

    def test_unchecked_low_level_call(self):
        source = 'contract C { function pay(address to) public { to.call{value: 1}(""); } }'
        report = audit_contract(source)
        self.assertIn("unchecked-low-level-call", {f.rule for f in report.findings})

    def test_checked_call_is_not_flagged(self):
        source = (
            'contract C { function pay(address to) public { '
            '(bool ok, ) = to.call{value: 1}(""); require(ok, "failed"); } }'
        )
        report = audit_contract(source)
        self.assertNotIn("unchecked-low-level-call", {f.rule for f in report.findings})

    def test_missing_access_control(self):
        source = "contract C { function withdraw() public { owner = msg.sender; } }"
        report = audit_contract(source)
        self.assertIn("missing-access-control", {f.rule for f in report.findings})
        guarded = source.replace("withdraw() public", "withdraw() public onlyOwner")
        self.assertNotIn("missing-access-control", {f.rule for f in audit_contract(guarded).findings})

    def test_comments_and_strings_are_masked(self):
        source = (
            "contract C {\n"
            '    // tx.origin == owner and to.call("");\n'
            '    string note = "tx.origin == owner";\n'
            "    function ping() public {}\n"
            "}\n"
        )
        self.assertTrue(audit_contract(source).clean)

    def test_findings_are_deterministic(self):
        first = audit_contract(REENTRANT + CLEAN)
        second = audit_contract(REENTRANT + CLEAN)
        self.assertEqual(first, second)
        self.assertEqual(
            [(f.line, f.rule) for f in first.findings],
            sorted((f.line, f.rule) for f in first.findings),
        )

    def test_source_loader_and_cli(self):
        with self.assertRaises(ValueError):
            load_source(None, None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contract.sol"
            path.write_text("contract C { function f() public {} }", encoding="utf-8")
            self.assertIn("function f", load_source(None, path))
            with self.assertRaises(ValueError):
                load_source("text", path)
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                output = main(["--file", str(path)])
            self.assertEqual(output, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["functions_scanned"], 1)
            self.assertTrue(payload["clean"])
        self.assertEqual(audit_contract("not solidity").functions_scanned, 0)


if __name__ == "__main__":
    unittest.main()
