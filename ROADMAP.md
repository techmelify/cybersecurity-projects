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

- [x] 01 Security News Scraper (Go → Python substitution) `S` — 21 tests passing
- [x] 02 Payload Obfuscation Detector (Go → Python defensive substitution) `◇` — 21 tests passing
- [x] 03 SIEM Dashboard (Flask/React → Python CLI substitution) `S` — 21 tests passing
- [x] 04 Token Abuse Playground (FastAPI/React → Python parse-only substitution) `◇` — 27 tests passing
- [x] 05 Supply Chain Attack Simulator (Python, defensive analyzer) `◇` — 24 tests passing
- [x] 06 DDoS Mitigation Tool (Go → Python offline simulation) `◇` — 22 tests passing
- [x] 07 Secrets Scanner (Go → Python substitution) `S` — 13 tests passing
- [x] 08 API Security Scanner (FastAPI/React → Python CLI substitution) `S` — 14 tests passing
- [x] 09 Wireless Deauth Detector (Rust → Python substitution) `◇` — 13 tests passing
- [x] 10 Credential Enumeration Detector (Nim → Python defensive substitution) `S` — 14 tests passing
- [x] 11 Binary Analysis Tool (Rust → Python substitution) `S` — 15 tests passing
- [x] 12 Chaos Engineering Security Tool (Go → Python simulation) `S` — 17 tests passing
- [x] 13 Credential Rotation Enforcer (Crystal → Python substitution) `S` — 9 tests passing
- [x] 14 Race Condition Detector (Python, defensive substitution) `◇` — 10 tests passing
- [x] 15 JA3/JA4 TLS Fingerprinting Tool (Rust → Python substitution) `S` — 9 tests passing
- [x] 16 Mobile App Security Analyzer (Python) `◇` — 9 tests passing
- [x] 17 DLP Scanner (Python) `S` — 11 tests passing
- [x] 18 Lua/Nginx Edge Backend (Python rule-engine substitution) `◇` — 9 tests passing
- [x] 19 Privesc Indicator Auditor (Python, defensive substitution) `◇` — 7 tests passing
- [x] 20 SBOM Generator & Vulnerability Matcher (Go → Python substitution) `S` — 7 tests passing
- [x] 21 Subdomain Takeover Scanner (Go → Python, snapshot-only) `◇` — 7 tests passing
- [x] 22 GraphQL Security Tester (Python, offline analyzer) `◇` — 8 tests passing
- [x] 23 Docker Security Audit (Go → Python substitution) `S` — 8 tests passing

## Advanced (22)

- [x] 01 API Rate Limiter (Python/Redis → stdlib simulation) `S` — 11 tests passing
- [x] 02 Encrypted Chat Application (FastAPI/SolidJS → Python local simulation) `S` — 14 tests passing
- [x] 03 Exploit Artifact Analyzer (C++ → Python defensive substitution) `◇` — 13 tests passing
- [x] 04 AI Threat Detection (Python statistical substitution) `S` — 16 tests passing
- [x] 05 Zingela Stateless Scanner (Zig → Python substitution) `S` — 14 tests passing
- [x] 06 Bug Bounty Platform (FastAPI/React → Python CLI substitution) `S` — 13 tests passing
- [x] 07 Cloud Security Compliance Dashboard (Go/React → Python CLI substitution) `◇` — 16 tests passing
- [x] 08 Malware Analysis Platform (Rust/Docker → Python static analyzer) `◇` — 15 tests passing
- [x] 09 Quantum Resistant Encryption (Python, toy Lamport OTS) `◇` — 17 tests passing
- [x] 10 Zero Day Vulnerability Scanner (Rust/C → Python defensive substitution) `S` — 14 tests passing
- [x] 11 Distributed Password Cracker (C++/CUDA → Python simulation) `◇` — 15 tests passing
- [x] 12 Kernel Rootkit Detection (Rust → Python substitution) `◇` — 14 tests passing
- [x] 13 Blockchain Smart Contract Auditor (Python static analyzer) `◇` — 9 tests passing
- [x] 14 Adversarial ML Detector (Python, defensive substitution) `◇` — 10 tests passing
- [x] 15 Reverse-Engineering Platform (C → Python substitution) `S` — 10 tests passing
- [x] 16 Hardware Security Module Emulator (Zig → Python substitution) `S` — 10 tests passing
- [x] 17 Network Covert Channel Detector (Rust → Python, defensive substitution) `◇` — 10 tests passing
- [x] 18 Automated Penetration Testing Planner (Python, defensive lab planner) `◇` — 10 tests passing
- [x] 19 Haskell Reverse Proxy (Python route-evaluator substitution) `S` — 9 tests passing
- [x] 20 "Monitor the Situation" Dashboard (Go/React → Python CLI substitution) `S` — 9 tests passing
- [x] 21 Honeypot Network (Go/React/Docker → Python simulator) `S` — 10 tests passing
- [x] 22 Supply Chain Security Analyzer (Go → Python substitution) `◇` — 9 tests passing

## Rules

- Offensive tools are lab-only; never point them at systems you do not own.
- No real malware samples in the repo; use synthetic fixtures.
- Tests must be deterministic and runnable without network access.
- Mark an item done only after tests pass locally.
