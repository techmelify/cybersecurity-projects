# 70-Project Roadmap

Built in order. `S` = reference source exists upstream, `◇` = synopsis only. The upstream README lists 69 distinct projects even though its badge says 70.

## Foundations (3)

- [x] 01 Hash Identifier `S` — 13 tests passing
- [x] 02 HTTP Headers Scanner `S` — 14 tests passing
- [x] 03 Password Manager `S` — 12 tests passing

## Beginner (21)

- [x] 01 Simple Port Scanner (C++ → Python substitution) `S` — 8 tests passing
- [x] 02 Keylogger (Python) `S` — 7 tests passing
- [x] 03 Caesar Cipher (Python) `S` — 12 tests passing
- [x] 04 DNS Lookup CLI Tool (Python) `S` — 8 tests passing
- [x] 05 Simple Vulnerability Scanner (Go → Python substitution) `S` — 8 tests passing
- [x] 06 Network Traffic Analyzer (C++ / Python → Python substitution) `S` — 6 tests passing
- [x] 07 Hash Cracker (C++ → Python substitution) `S` — 10 tests passing
- [x] 08 Steganography Multi-Tool (Go → Python substitution) `S` — 9 tests passing
- [x] 09 Deserialization Gadget Lab (Ruby → Python substitution) `S` — 5 tests passing
- [x] 10 Canary Token Generator (Go/React → Python CLI substitution) `S` — 7 tests passing
- [x] 11 Phishing Domain Detector & Quishing Scanner (Python, defensive-only) `◇` — 9 tests passing
- [x] 12 SSH Brute Force Detector (Python) `◇` — 8 tests passing
- [x] 13 Simple C2 Beacon (Python, offline simulator/detector) `S` — 7 tests passing
- [x] 14 Base64 Encoder/Decoder (Python) `S` — 6 tests passing
- [x] 15 Linux CIS Hardening Auditor (Bash → Python substitution) `S` — 5 tests passing
- [x] 16 Systemd Persistence Scanner (Go → Python substitution) `S` — 6 tests passing
- [x] 17 Linux eBPF Security Tracer (Python, offline event analyzer) `S` — 7 tests passing
- [x] 18 Trojan Application Detector (Python, defensive substitution) `◇` — 6 tests passing
- [x] 19 DNS Sinkhole (Go → Python substitution) `◇` — 6 tests passing
- [x] 20 Firewall Rule Engine (V → Python substitution) `S` — 7 tests passing
- [x] 21 LLM Prompt Injection Firewall (Python) `S` — 7 tests passing

## Intermediate (23)

- [ ] 01 Security News Scraper (Go) `S`
- [ ] 02 Payload Obfuscation Engine (Go) `◇`
- [ ] 03 SIEM Dashboard (Flask/React) `S`
- [ ] 04 Token Abuse Playground (FastAPI/React) `◇`
- [ ] 05 Supply Chain Attack Simulator (Python) `◇`
- [ ] 06 DDoS Mitigation Tool (Go) `◇`
- [ ] 07 Secrets Scanner (Go) `S`
- [ ] 08 API Security Scanner (FastAPI/React) `S`
- [ ] 09 Wireless Deauth Detector (Rust) `◇`
- [ ] 10 Credential Enumeration (Nim) `S`
- [ ] 11 Binary Analysis Tool (Rust) `S`
- [ ] 12 Chaos Engineering Security Tool (Go) `S`
- [ ] 13 Credential Rotation Enforcer (Crystal) `S`
- [ ] 14 Race Condition Exploiter (FastAPI/React) `◇`
- [ ] 15 JA3/JA4 TLS Fingerprinting Tool (Rust) `S`
- [ ] 16 Mobile App Security Analyzer (Python) `◇`
- [ ] 17 DLP Scanner (Python) `S`
- [ ] 18 Lua/Nginx Edge Backend (Lua/Nginx) `◇`
- [ ] 19 Privesc Playground (Python) `◇`
- [ ] 20 SBOM Generator & Vulnerability Matcher (Go) `S`
- [ ] 21 Subdomain Takeover Scanner (Go) `◇`
- [ ] 22 GraphQL Security Tester (Python) `◇`
- [ ] 23 Docker Security Audit (Go) `S`

## Advanced (22)

- [ ] 01 API Rate Limiter (Python/Redis) `S`
- [ ] 02 Encrypted Chat Application (FastAPI/SolidJS) `S`
- [ ] 03 Exploit Development Framework (C++) `◇`
- [ ] 04 AI Threat Detection (FastAPI/React/PyTorch) `S`
- [ ] 05 Zingela Stateless Scanner (Zig) `S`
- [ ] 06 Bug Bounty Platform (FastAPI/React) `S`
- [ ] 07 Cloud Security Compliance Dashboard (Go/React) `◇`
- [ ] 08 Malware Analysis Platform (Rust/Docker) `◇`
- [ ] 09 Quantum Resistant Encryption (Python) `◇`
- [ ] 10 Zero Day Vulnerability Scanner (Rust/C) `S`
- [ ] 11 Distributed Password Cracker (C++/CUDA) `◇`
- [ ] 12 Kernel Rootkit Detection (Rust) `◇`
- [ ] 13 Blockchain Smart Contract Auditor (Python/Solidity) `◇`
- [ ] 14 Adversarial ML Attacker (Python/TensorFlow) `◇`
- [ ] 15 Reverse-Engineering Platform (C) `S`
- [ ] 16 Hardware Security Module Emulator (Zig) `S`
- [ ] 17 Network Covert Channel (Rust) `◇`
- [ ] 18 Automated Penetration Testing (Python) `◇`
- [ ] 19 Haskell Reverse Proxy `S`
- [ ] 20 "Monitor the Situation" Dashboard (Go/React) `S`
- [ ] 21 Honeypot Network (Go/React/Docker) `S`
- [ ] 22 Supply Chain Security Analyzer (Go) `◇`

## Rules

- Offensive tools are lab-only; never point them at systems you do not own.
- No real malware samples in the repo; use synthetic fixtures.
- Tests must be deterministic and runnable without network access.
- Mark an item done only after tests pass locally.
