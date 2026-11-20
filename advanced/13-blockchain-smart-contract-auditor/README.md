# 13 — Blockchain Smart Contract Auditor

A deterministic static analyzer for **synthetic Solidity source text**. It flags four common contract pitfalls before deployment:

| Rule | Severity | Trigger |
| --- | --- | --- |
| `reentrancy` | high | External call appears before a state update in the same function. |
| `tx-origin-auth` | high | `tx.origin` is used for identity or authorisation. |
| `unchecked-low-level-call` | medium | `call` / `send` / `delegatecall` result is not checked. |
| `missing-access-control` | high | A privileged function has no owner/admin modifier or check. |

## Run

```powershell
python contract_auditor.py "function withdraw() public { msg.sender.call{value: 1}(""); balances[msg.sender] = 0; }"
python contract_auditor.py --file sample.sol
```

Output is JSON with `findings` (rule, severity, 1-based line, message), `functions_scanned`, and `clean`.

## Scope and substitutions

- The upstream catalogue lists this as a synopsis-only Python/Solidity project. This implementation is original Python and **does not compile or execute Solidity**.
- No blockchain node, wallet, RPC endpoint, network call, or real credentials are used. Input is plain text; fixtures are synthetic.
- Comments and string literals are masked before scanning so line numbers stay accurate and documentation cannot create false hits.

## Test

```powershell
python -m unittest discover -s tests -v
```

9 tests, standard library only.

## Limitations

This is a pattern-based review aid, not a formal verifier. It cannot reason about cross-function or cross-contract state, compiler versions, or economic logic. A clean report is not a security guarantee; always combine it with manual review and proper tooling.
