# Learn — smart-contract review heuristics

## Why static review matters

Contract code is immutable after deployment in many designs, so bugs found later are expensive. A cheap textual pre-check catches recurring mistakes before a deeper review.

## The four patterns

1. **Reentrancy** — if an external call happens before balances are updated, the callee can call back and spend the same balance twice. The Checks-Effects-Interactions pattern reverses that order.
2. **tx.origin authentication** — `tx.origin` is the externally owned account that started the chain of calls, not the immediate caller. A phishing contract can trick it into passing an owner check. Use `msg.sender` or a role modifier.
3. **Unchecked low-level calls** — `call`, `send`, and `delegatecall` return a boolean. Ignoring it silently turns failures into apparent successes.
4. **Missing access control** — functions that move funds, mint tokens, or change ownership must verify the caller's authority.

## How this tool works

Comments and string literals are blanked out (newlines preserved), functions are located by brace matching, and each rule inspects the masked source. Findings are sorted by line and rule so output is stable. Everything is pure text processing: no compiler, chain, or network.
