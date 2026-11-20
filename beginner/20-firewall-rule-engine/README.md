<div align="center">
  <img src="assets/hero.svg" alt="Firewall Rule Engine banner" width="100%" />
</div>

<br />

<div align="center">

# 🧱 Firewall Rule Engine

![Tier](https://img.shields.io/badge/tier-BEGINNER-60A5FA?style=for-the-badge)
![Domain](https://img.shields.io/badge/domain-Network%20Defense-1E3A5F?style=for-the-badge)
![Language](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-7%20passing-16A34A?style=for-the-badge)
![Deps](https://img.shields.io/badge/deps-standard%20library-gray?style=for-the-badge)

> **First match wins.** A tiny policy engine that decides whether a packet is allowed — and tells you exactly which rule made the call.

</div>

---

## 🎯 What it does

It reads an ordered list of JSON rules and evaluates one synthetic packet against them. Each rule can constrain source subnet, destination subnet, port, port range, port list, and protocol. The first matching rule decides the outcome; if nothing matches, the packet is denied.

This is the decision core of a firewall, stripped down to something you can read in one sitting.

## 🧠 How it works

```mermaid
flowchart LR
    A[Packet<br/>src · dst · port · proto] --> B{Rule 1 matches?}
    B -- yes --> Z[ALLOW / DENY<br/>rule name]
    B -- no --> C{Rule 2 matches?}
    C -- yes --> Z
    C -- no --> D{...more rules}
    D -- match --> Z
    D -- exhausted --> E[Default DENY]
```

Matching rules use `ipaddress` for CIDR checks and a small port parser that accepts `443`, `80-443`, or `80,443`.

## 🚀 Quick start

```powershell
python firewall.py rules.json --src 8.8.8.8 --dst 10.2.3.4 --port 443
```

Example `rules.json`:

```json
[
  {"name": "allow-web",   "action": "allow", "dst": "10.0.0.0/8",     "port": "80,443", "protocol": "tcp"},
  {"name": "allow-admin", "action": "allow", "src": "192.168.1.0/24", "port": "22",     "protocol": "tcp"},
  {"name": "deny-all",    "action": "deny"}
]
```

### Real output

```text
$ python firewall.py rules.json --src 8.8.8.8 --dst 10.2.3.4 --port 443
ALLOW (allow-web)

$ python firewall.py rules.json --src 203.0.113.9 --dst 10.2.3.4 --port 3389
DENY (deny-all)

$ python firewall.py rules.json --src 192.168.1.25 --dst 10.0.0.1 --port 22
ALLOW (allow-admin)
```

## 📂 Project structure

```text
20-firewall-rule-engine/
├── assets/hero.svg          # generated visual identity
├── firewall.py              # rule model + evaluator + CLI
├── learn/README.md          # the concepts behind first-match policies
└── tests/test_firewall.py   # 7 deterministic tests
```

## 🔍 Why it matters

- **Order is security.** A broad `allow` placed above a specific `deny` silently defeats the deny rule.
- **Default deny** turns an accidental omission into a safe outcome.
- **Attribution** matters: returning the *rule name* makes policy debugging possible.

## 🧪 Tests

```powershell
python -m unittest discover -s tests -v
```

7 tests covering CIDR matching, port lists and ranges, protocol filtering, first-match precedence, default deny, rule loading, and the CLI.

## 📚 Learn more

Read [the concept notes](learn/README.md) for first-match semantics, default-deny baselines, and how matching dimensions combine.

---

<div align="center">
  <sub>Part of <b>cybersecurity-projects</b> · Beginner tier · Built from a synopsis, original implementation.</sub>
</div>
