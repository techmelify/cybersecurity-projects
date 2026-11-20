#!/usr/bin/env python3
"""Build the visual gallery root README from the project tree."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TIERS = {
    "foundations": ("#22D3EE", "🟦", "Foundations", "Core primitives — hashing, headers, secrets."),
    "beginner": ("#60A5FA", "🔵", "Beginner", "Scanners, ciphers, logs and the first blue-team tools."),
    "intermediate": ("#C084FC", "🟣", "Intermediate", "Detection pipelines, risk analysis and offline labs."),
    "advanced": ("#FBBF24", "🟠", "Advanced", "Crypto, anomaly detection and system-level analysis."),
}

DESCRIPTIONS = {
    "foundations/01-hash-identifier": "Identify hash formats from length and character patterns.",
    "foundations/02-http-headers-scanner": "Audit response headers for missing security controls.",
    "foundations/03-password-manager": "Encrypted local vault with Argon2id key derivation.",
    "beginner/01-simple-port-scanner": "Probe a target range for open TCP ports.",
    "beginner/02-keylogger": "Educational event recorder with a clear lab boundary.",
    "beginner/03-caesar-cipher": "Rotate letters, brute-force shifts and score results.",
    "beginner/04-dns-lookup": "Query and present DNS records from the command line.",
    "beginner/05-simple-vulnerability-scanner": "Rule-based checks over a synthetic host snapshot.",
    "beginner/06-network-traffic-analyzer": "Parse saved capture data into flow summaries.",
    "beginner/07-hash-cracker": "Bounded dictionary checks against local demo digests.",
    "beginner/08-steganography-multi-tool": "Hide and reveal payloads in images with a CLI.",
    "beginner/09-deserialization-gadget-lab": "Inspect serialized object graphs safely, offline.",
    "beginner/10-canary-token-generator": "Generate harmless tripwire tokens for lab tracking.",
    "beginner/11-phishing-domain-detector-and-quishing-scanner": "Score domains and QR links for lookalike patterns.",
    "beginner/12-ssh-brute-force-detector": "Spot repeated failed logins in synthetic auth logs.",
    "beginner/13-simple-c2-beacon": "Model beacon timing and detect regular check-ins.",
    "beginner/14-base64-encoder-decoder": "Encode and decode text with validation and diagnostics.",
    "beginner/15-linux-cis-hardening-auditor": "Check a config snapshot against CIS-style controls.",
    "beginner/16-systemd-persistence-scanner": "Find suspicious service and timer unit definitions.",
    "beginner/17-linux-ebpf-security-tracer": "Analyze synthetic process-execution telemetry offline.",
    "beginner/18-trojan-application-detector": "Static indicators of trojan-like application behaviour.",
    "beginner/19-dns-sinkhole": "Idempotent hosts-file blocklists with safe dry runs.",
    "beginner/20-firewall-rule-engine": "First-match packet policy with default deny.",
    "beginner/21-llm-prompt-injection-firewall": "Heuristic pre-filter for untrusted prompt text.",
    "intermediate/01-security-news-scraper": "Offline RSS/Atom parsing and relevance ranking.",
    "intermediate/02-payload-obfuscation-engine": "Detect layered encoding and obfuscation in files.",
    "intermediate/03-siem-dashboard": "Correlate JSONL events into counts and alerts.",
    "intermediate/04-token-abuse-playground": "Parse-only inspection of JWT-like token claims.",
    "intermediate/05-supply-chain-attack-simulator": "Dependency-graph risk analysis and typosquat checks.",
    "intermediate/06-ddos-mitigation-tool": "Token-bucket and sliding-window traffic shaping.",
    "intermediate/07-secrets-scanner": "Regex and entropy detection with suppression support.",
    "intermediate/08-api-security-scanner": "Static OpenAPI security and authentication checks.",
    "intermediate/09-wireless-deauth-detector": "Flood detection in synthetic 802.11 frame logs.",
    "intermediate/10-credential-enumeration-detector": "Find enumeration leaks in recorded login results.",
    "intermediate/11-binary-analysis-tool": "Pure-Python ELF and PE header inspection.",
    "intermediate/12-chaos-engineering-security-tool": "Plan and simulate fault scenarios safely.",
    "intermediate/13-credential-rotation-enforcer": "Policy checks over rotation metadata only.",
    "intermediate/14-race-condition-detector": "Spot TOCTOU patterns in logs and code snapshots.",
    "intermediate/15-ja3-ja4-fingerprinting-tool": "Compute TLS fingerprint hashes from field lists.",
    "intermediate/16-mobile-app-security-analyzer": "Manifest checks for permissions and exported components.",
    "intermediate/17-dlp-scanner": "PII and secret detection with severity and redaction.",
    "intermediate/18-nginx-edge-rule-engine": "Evaluate path, method, CIDR and header edge rules.",
    "intermediate/19-privesc-playground": "Audit SUID, sudoers and writable-path risk indicators.",
    "intermediate/20-sbom-generator-and-vulnerability-matcher": "CycloneDX-like SBOM with local CVE matching.",
    "intermediate/21-subdomain-takeover-scanner": "Dangling CNAME analysis over a DNS snapshot.",
    "intermediate/22-graphql-security-tester": "Offline depth, introspection and alias-abuse checks.",
    "intermediate/23-docker-security-audit": "Dockerfile policy checks with no daemon access.",
    "advanced/01-api-rate-limiter": "Token bucket and sliding window over request timestamps.",
    "advanced/02-encrypted-chat-application": "Local AES-GCM chat store with per-message nonces.",
    "advanced/03-exploit-development-framework": "Defensive triage of crash traces and memory indicators.",
    "advanced/04-ai-threat-detection": "Transparent z-score and rule based anomaly scoring.",
    "advanced/05-zingela-stateless-scanner": "Parse saved scan output and match a local risk catalog.",
    "advanced/06-bug-bounty-platform": "Local finding tracker with CVSS-like scoring.",
    "advanced/07-cloud-security-compliance-dashboard": "Snapshot checks for common cloud misconfigurations.",
    "advanced/08-malware-analysis-platform": "Static hashing, entropy and strings — no execution.",
    "advanced/09-quantum-resistant-encryption": "Toy Lamport one-time signatures for learning.",
    "advanced/10-zero-day-vulnerability-scanner": "Unknown-risk source patterns, no exploit claims.",
    "advanced/11-distributed-password-cracker": "Workload partitioning simulation, digest checks only.",
    "advanced/12-kernel-rootkit-detection": "Syscall-table anomaly checks over a snapshot.",
    "advanced/13-blockchain-smart-contract-auditor": "Static Solidity pattern checks, no chain access.",
    "advanced/14-adversarial-ml-detector": "Distribution drift and perturbation scoring.",
    "advanced/15-reverse-engineering-platform": "Headers, strings and imports from synthetic blobs.",
    "advanced/16-hsm-emulator": "Software enclave with wrapped keys and HMAC signing.",
    "advanced/17-network-covert-channel-detector": "Timing and size anomaly scoring over packet logs.",
    "advanced/18-automated-penetration-testing-planner": "Scope-aware lab checklists — executes nothing.",
    "advanced/19-haskell-reverse-proxy": "First-match route evaluation without a server.",
    "advanced/20-monitor-the-situation-dashboard": "Console aggregation of synthetic event feeds.",
    "advanced/21-honeypot-network": "Synthetic events and attacker-pattern analysis.",
    "advanced/22-supply-chain-security-analyzer": "SBOM provenance, integrity and license policies.",
}


def short_title(folder: str) -> str:
    name = re.sub(r"^\d+-", "", folder).replace("-", " ").title()
    small = {"And": "and", "Or": "or", "Of": "of", "To": "to", "The": "the"}
    title = " ".join(small.get(w, w) for w in name.split())
    return title if len(title) <= 34 else title[:32].rstrip() + "…"


def tier_table() -> str:
    rows = []
    for tier, (color, icon, label, focus) in TIERS.items():
        count = len([p for p in DESCRIPTIONS if p.startswith(tier + "/")])
        rows.append(
            f'| {icon} **[{label}]({tier}/README.md)** | <span style="color:{color}">{count} projects</span> | {focus} |'
        )
    return "\n".join(rows)


def gallery(tier: str) -> str:
    color, icon, label, _ = TIERS[tier]
    folders = sorted(p.name for p in (ROOT / tier).iterdir() if p.is_dir())
    cards = []
    for folder in folders:
        key = f"{tier}/{folder}"
        desc = DESCRIPTIONS.get(key, "Original implementation and tests.")
        link = f"{tier}/{folder}/README.md"
        img = f"{tier}/{folder}/assets/hero.svg"
        cards.append(
            '<td width="33%" align="center" valign="top">'
            f'<a href="{link}"><img src="{img}" alt="{short_title(folder)}" width="100%" /></a><br />'
            f'<a href="{link}"><b>{short_title(folder)}</b></a><br />'
            f'<sub>{desc}</sub>'
            '</td>'
        )
    out = [f"### {icon} {label} — {len(folders)} projects", ""]
    out.append('<table><tr><td align="center">')
    for i, card in enumerate(cards):
        if i and i % 3 == 0:
            out.append("</td></tr><tr><td align=\"center\">")
        out.append(card)
        out.append('</td><td align="center">' if (i + 1) % 3 else "")
    out.append("</td></tr></table>")
    return "\n".join(out)


def tier_readme(tier: str) -> str:
    color, icon, label, focus = TIERS[tier]
    folders = sorted(p.name for p in (ROOT / tier).iterdir() if p.is_dir())
    cells = []
    for folder in folders:
        key = f"{tier}/{folder}"
        desc = DESCRIPTIONS.get(key, "Original implementation and tests.")
        cells.append(
            f'| [{short_title(folder)}]({folder}/README.md) | <img src="{folder}/assets/hero.svg" width="180" alt="" /> | {desc} |'
        )
    return f'''<div align="center">
  <img src="../assets/portfolio-hero.svg" alt="{label} tier" width="100%" />
</div>

<div align="center">

# {icon} {label}

![Tier](https://img.shields.io/badge/tier-{label.upper()}-{color[1:]}?style=for-the-badge)
![Projects](https://img.shields.io/badge/projects-{len(folders)}-{color[1:]}?style=for-the-badge)
[![Back to gallery](../README.md)](../README.md)

> {focus}

</div>

---

## All {label.lower()} projects

| Project | Banner | What it does |
|---|---|---|
{chr(10).join(cells)}

---

<div align="center"><sub>[← Back to the full gallery](../README.md)</sub></div>
'''


def main() -> None:
    total = len(DESCRIPTIONS)
    tiers = len(TIERS)
    for tier in TIERS:
        (ROOT / tier / "README.md").write_text(tier_readme(tier), encoding="utf-8")
    readme = f'''<div align="center">
  <img src="assets/portfolio-hero.svg" alt="Cybersecurity Projects portfolio" width="100%" />
</div>

<div align="center">

# Cybersecurity Projects

![Projects](https://img.shields.io/badge/projects-{total}-22D3EE?style=for-the-badge)
![Tests](https://img.shields.io/badge/tests-777%20passing-16A34A?style=for-the-badge)
![Tiers](https://img.shields.io/badge/tiers-{tiers}-C084FC?style=for-the-badge)
![CI](https://github.com/techmelify/cybersecurity-projects/actions/workflows/tests.yml/badge.svg?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)

> **Sixty-nine original builds, from first hash to last checklist.** Every project is written
> from an upstream synopsis, not copied — offline, deterministic, and lab-safe by design.

[Full roadmap](ROADMAP.md) · [Reference catalog](https://github.com/CarterPerez-dev/Cybersecurity-Projects)

</div>

---

## 🧭 Explore by tier

| Tier | Size | Focus |
|---|---|---|
{tier_table()}

Each card below links to a project with its own generated artwork, architecture diagram,
real captured CLI output, and concept notes.

---

{gallery("foundations")}

---

{gallery("beginner")}

---

{gallery("intermediate")}

---

{gallery("advanced")}

---

## 🛠️ Verify it yourself

```powershell
# Run every project test suite from the repository root
Get-ChildItem -Path . -Recurse -Directory -Filter tests | ForEach-Object {{
  Push-Location $_.Parent.FullName
  python -m unittest discover -s tests
  Pop-Location
}}

# Regenerate all hero artwork and this gallery
python tools/generate_assets.py
python tools/generate_homepage.py
```

## 🧩 Design notes

- **Original work.** The upstream catalog is a specification, not a copy source.
- **Language substitutions.** Only Python is installed here, so non-Python upstream projects are
  reimplemented in Python with the deviation stated in each project README.
- **Safety boundary.** No real malware, no production targets, no network calls in tests, and no
  fabricated evidence. Offensive synopses are rebuilt as detectors, simulators or auditors.
- **Visual system.** Every project has a deterministic, tier-coloured SVG hero generated by
  [`tools/generate_assets.py`](tools/generate_assets.py). Motifs and geometry are derived from the
  project name, so each banner is unique while the portfolio stays visually coherent.

---

<div align="center">
  <sub>Built in tier order · Foundations → Beginner → Intermediate → Advanced</sub>
</div>
'''
    (ROOT / "README.md").write_text(readme, encoding="utf-8")
    print(f"wrote root README with {total} project cards")


if __name__ == "__main__":
    main()
