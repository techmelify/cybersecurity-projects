#!/usr/bin/env python3
"""Deterministic, unique hero-banner generator for every portfolio project.

Each project gets an SVG illustration chosen from a motif library. The motif,
palette, geometry and composition are derived from the project's folder name,
so every banner is distinct yet the whole portfolio shares one visual language.

Tier palettes:
    foundations   cyan      #22D3EE
    beginner      blue      #60A5FA
    intermediate  violet    #C084FC
    advanced      amber     #FBBF24

Run from the repository root:
    python tools/generate_assets.py
"""

from __future__ import annotations

import hashlib
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PALETTES = {
    "foundations": ("#22D3EE", "#0891B2", "FOUNDATIONS"),
    "beginner": ("#60A5FA", "#2563EB", "BEGINNER"),
    "intermediate": ("#C084FC", "#9333EA", "INTERMEDIATE"),
    "advanced": ("#FBBF24", "#D97706", "ADVANCED"),
}

# keyword -> motif. First match wins; order matters.
KEYWORD_MOTIFS = [
    (("firewall", "rule", "proxy", "nginx", "edge", "rate", "gateway"), "shield"),
    (("hash", "cipher", "base64", "quantum", "encrypt", "token", "lamport", "hsm"), "matrix"),
    (("password", "credential", "secret", "vault", "dlp", "canary"), "lock"),
    (("scanner", "detect", "audit", "analyz", "analy", "tester", "hunt"), "radar"),
    (("network", "traffic", "dns", "port", "covert", "ddos", "wireless", "honeypot", "sinkhole"), "nodes"),
    (("malware", "trojan", "exploit", "rootkit", "reverse", "binary", "artifact", "obfusc"), "chip"),
    (("siem", "dashboard", "monitor", "threat", "situation", "bug", "bounty"), "graph"),
    (("supply", "sbom", "docker", "blockchain", "cloud", "compliance"), "constellation"),
    (("phishing", "keylog", "beacon", "persistence", "privesc", "race", "chaos"), "wave"),
    (("llm", "prompt", "ai", "adversarial", "ml"), "neural"),
    (("stego", "deserial", "gadget", "graphql", "api"), "braces"),
]


def choose_motif(folder: str) -> str:
    low = folder.lower()
    for keywords, motif in KEYWORD_MOTIFS:
        if any(k in low for k in keywords):
            return motif
    return ("orbit", "circuit", "signal", "lattice")[int(hashlib.md5(folder.encode()).hexdigest(), 16) % 4]


def title_case(folder: str) -> str:
    part = re.sub(r"^\d+-", "", folder)
    part = part.replace("-", " ").title()
    small = {"And": "and", "Or": "or", "Of": "of", "To": "to", "The": "the"}
    return " ".join(small.get(w, w) for w in part.split())


def project_number(folder: str) -> str:
    m = re.match(r"^(\d+)-", folder)
    return m.group(1) if m else "00"


def _grid() -> str:
    return (
        '<defs>'
        '<pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">'
        '<path d="M40 0H0V40" fill="none" stroke="#1E293B" stroke-width="1" opacity="0.45"/>'
        '</pattern>'
        '<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0%" stop-color="#0B1220"/><stop offset="100%" stop-color="#070B14"/>'
        '</linearGradient>'
        '<filter id="glow" x="-50%" y="-50%" width="200%" height="200%">'
        '<feGaussianBlur stdDeviation="6" result="b"/><feMerge>'
        '<feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
        '</defs>'
        '<rect width="1200" height="360" fill="url(#bg)"/>'
        '<rect width="1200" height="360" fill="url(#grid)"/>'
    )


def _motif(name: str, rnd: random.Random, accent: str, accent2: str) -> str:
    """Return artwork drawn in the right-hand 560x300 region (origin 600,30)."""
    ox, oy = 900, 180
    p: list[str] = []
    g = f'<g transform="translate({ox} {oy})" fill="none" stroke="{accent}" stroke-width="2" opacity="0.92">'

    if name == "shield":
        p.append(g)
        p.append('<path d="M0 -95 L86 -60 L80 45 Q60 88 0 110 Q-60 88 -80 45 L-86 -60 Z" opacity="0.35"/>')
        p.append('<path d="M0 -70 L64 -43 L59 36 Q44 66 0 84 Q-44 66 -59 36 L-64 -43 Z"/>')
        for i in range(4):
            y = -35 + i * 28
            p.append(f'<path d="M-46 {y} H46" opacity="{0.25 + i * 0.16:.2f}"/>')
        p.append(f'<circle cx="0" cy="5" r="13" fill="{accent2}" opacity="0.8" stroke="none"/>')
        p.append('</g>')

    elif name == "matrix":
        p.append(g)
        glyphs = "0123456789ABCDEF"
        for col in range(9):
            x = -96 + col * 24
            for row in range(9):
                ch = rnd.choice(glyphs)
                op = round(rnd.uniform(0.18, 0.95), 2)
                p.append(
                    f'<text x="{x}" y="{-80 + row * 21}" fill="{accent}" stroke="none" '
                    f'font-family="monospace" font-size="13" opacity="{op}">{ch}</text>'
                )
        p.append(f'<rect x="-104" y="-92" width="208" height="184" stroke="{accent2}" opacity="0.4"/>')
        p.append('</g>')

    elif name == "lock":
        p.append(g)
        p.append('<rect x="-70" y="-10" width="140" height="105" rx="12" opacity="0.5"/>')
        p.append('<path d="M-40 -10 V-46 A40 40 0 0 1 40 -46 V-10"/>')
        p.append(f'<circle cx="0" cy="34" r="16" fill="{accent2}" stroke="none" opacity="0.85"/>')
        p.append('<path d="M0 34 V52" stroke="#070B14" stroke-width="4"/>')
        for i in range(5):
            x = -60 + i * 30
            p.append(f'<path d="M{x} -95 L{x} -80" opacity="0.5"/>')
        p.append('</g>')

    elif name == "radar":
        p.append(g)
        for r in (30, 62, 95):
            p.append(f'<circle cx="0" cy="0" r="{r}" opacity="{0.7 - r / 200:.2f}"/>')
        p.append(f'<path d="M0 0 L{rnd.randint(40, 90)} {rnd.randint(-85, 85)}" stroke="{accent2}" stroke-width="3"/>')
        p.append('<path d="M-120 0H120M0 -120V120" opacity="0.25"/>')
        for _ in range(4):
            a = rnd.uniform(0, 6.28)
            rr = rnd.uniform(25, 92)
            x, y = rr * __import__("math").cos(a), rr * __import__("math").sin(a)
            p.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{accent}" stroke="none"/>')
        p.append('</g>')

    elif name == "nodes":
        p.append(g)
        pts = [(rnd.randint(-105, 105), rnd.randint(-95, 95)) for _ in range(9)]
        for i, (x, y) in enumerate(pts):
            for j in range(i + 1, len(pts)):
                x2, y2 = pts[j]
                if ((x - x2) ** 2 + (y - y2) ** 2) ** 0.5 < 78:
                    p.append(f'<path d="M{x} {y} L{x2} {y2}" opacity="0.25"/>')
        for i, (x, y) in enumerate(pts):
            r = 7 if i % 3 == 0 else 4
            fill = accent2 if i % 3 == 0 else accent
            p.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}" stroke="none"/>')
        p.append('</g>')

    elif name == "chip":
        p.append(g)
        p.append('<rect x="-62" y="-62" width="124" height="124" rx="10" opacity="0.6"/>')
        p.append(f'<rect x="-34" y="-34" width="68" height="68" rx="6" stroke="{accent2}"/>')
        for i in range(6):
            q = -50 + i * 20
            p.append(f'<path d="M{q} -62 V-84 M{q} 62 V84 M-62 {q} H-84 M62 {q} H84" opacity="0.55"/>')
        p.append('</g>')

    elif name == "graph":
        p.append(g)
        p.append('<path d="M-110 90 H110 M-110 90 V-100" opacity="0.35"/>')
        bars = [rnd.randint(25, 130) for _ in range(9)]
        for i, h in enumerate(bars):
            x = -95 + i * 24
            p.append(f'<rect x="{x}" y="{90 - h}" width="14" height="{h}" fill="{accent}" stroke="none" opacity="{0.35 + i * 0.07:.2f}"/>')
        p.append(f'<path d="M-95 20 L-71 5 L-47 30 L-23 -12 L1 18 L25 -30 L49 -8 L73 -52 L97 -20" stroke="{accent2}" stroke-width="3"/>')
        p.append('</g>')

    elif name == "constellation":
        p.append(g)
        centers = [(rnd.randint(-90, 90), rnd.randint(-80, 80)) for _ in range(6)]
        for i, (x, y) in enumerate(centers):
            p.append(f'<circle cx="{x}" cy="{y}" r="{20 + i * 3}" opacity="{0.5 - i * 0.05:.2f}"/>')
            p.append(f'<circle cx="{x}" cy="{y}" r="5" fill="{accent2}" stroke="none"/>')
            if i:
                px, py = centers[i - 1]
                p.append(f'<path d="M{px} {py} L{x} {y}" opacity="0.3"/>')
        p.append('</g>')

    elif name == "wave":
        p.append(g)
        pts = []
        for i in range(45):
            x = -110 + i * 5
            y = int(-10 + rnd.uniform(-1, 1) * (18 if i % 7 else 75))
            pts.append(f"{x},{y}")
        p.append(f'<polyline points="{" ".join(pts)}" stroke="{accent}" opacity="0.85"/>')
        p.append(f'<path d="M-110 0H110" stroke="{accent2}" opacity="0.35" stroke-dasharray="6 6"/>')
        p.append('</g>')

    elif name == "neural":
        p.append(g)
        layers = [(-90, 5), (0, 7), (90, 5)]
        coords = []
        for lx, count in layers:
            col = [(lx, -70 + i * (140 / max(count - 1, 1))) for i in range(count)]
            coords.append(col)
        for a, b in zip(coords, coords[1:]):
            for x1, y1 in a:
                for x2, y2 in b:
                    p.append(f'<path d="M{x1:.0f} {y1:.0f} L{x2:.0f} {y2:.0f}" opacity="0.22"/>')
        for col in coords:
            for x, y in col:
                p.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="6" fill="{accent2}" stroke="none"/>')
        p.append('</g>')

    elif name == "braces":
        p.append(g)
        lines = [
            ("M-40 -90 Q-75 -90 -75 -55 V-35 Q-75 -20 -90 -20 Q-75 -20 -75 -5 V15 Q-75 50 -40 50", accent),
            ("M40 -90 Q75 -90 75 -55 V-35 Q75 -20 90 -20 Q75 -20 75 -5 V15 Q75 50 40 50", accent),
            ("M-20 -30 L-35 10 M20 -30 L35 10", accent2),
        ]
        for d, col in lines:
            p.append(f'<path d="{d}" stroke="{col}" stroke-width="4" filter="url(#glow)"/>')
        p.append('</g>')

    else:  # orbit / circuit / signal / lattice fallbacks
        p.append(g)
        p.append('<circle r="92" opacity="0.3"/>')
        p.append('<circle r="58" opacity="0.45"/>')
        for i in range(12):
            import math
            a = i * (6.283 / 12) + rnd.uniform(-0.1, 0.1)
            r = 92
            x, y = r * math.cos(a), r * math.sin(a)
            p.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{4 + (i % 3) * 2}" fill="{accent if i % 2 else accent2}" stroke="none"/>')
        p.append(f'<path d="M-92 0 A92 92 0 0 1 0 -92" stroke="{accent2}" stroke-width="4" filter="url(#glow)"/>')
        p.append('</g>')

    return "".join(p)


def banner(tier: str, folder: str) -> str:
    accent, accent2, tier_label = PALETTES[tier]
    rnd = random.Random(hashlib.sha256(folder.encode()).hexdigest())
    motif = choose_motif(folder)
    num = project_number(folder)
    name = title_case(folder)

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 360" width="1200" height="360" role="img" aria-label="{name} banner">
{_grid()}
<rect x="0" y="0" width="1200" height="6" fill="{accent}"/>
<rect x="0" y="354" width="1200" height="6" fill="{accent}"/>
<text x="60" y="92" fill="{accent}" font-family="Consolas,Monaco,monospace" font-size="22" letter-spacing="6" opacity="0.9">{tier_label} / {num}</text>
<text x="60" y="176" fill="#F8FAFC" font-family="Segoe UI,Arial,sans-serif" font-size="52" font-weight="700">{name}</text>
<rect x="60" y="206" width="120" height="4" fill="{accent2}"/>
<text x="60" y="252" fill="#94A3B8" font-family="Consolas,Monaco,monospace" font-size="18">cybersecurity-projects / {tier}</text>
<rect x="600" y="20" width="2" height="320" fill="{accent}" opacity="0.18"/>
{_motif(motif, rnd, accent, accent2)}
</svg>'''
    return svg


def portfolio_banner() -> str:
    """Top-level portfolio hero tying the four tier colours together."""
    colors = [PALETTES[t][0] for t in ("foundations", "beginner", "intermediate", "advanced")]
    rings = "".join(
        f'<circle cx="1010" cy="200" r="{150 - i * 26}" fill="none" stroke="{c}" '
        f'stroke-width="3" opacity="{0.75 - i * 0.12:.2f}"/>'
        for i, c in enumerate(colors)
    )
    nodes = "".join(
        f'<circle cx="{1010 + (150 - i * 26)}" cy="200" r="7" fill="{c}"/>'
        for i, c in enumerate(colors)
    )
    bars = "".join(
        f'<rect x="{70 + i * 34}" y="316" width="22" height="{26 + i * 9}" fill="{c}" opacity="0.85"/>'
        for i, c in enumerate(colors)
    )
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 400" width="1200" height="400" role="img" aria-label="Cybersecurity Projects portfolio banner">
<defs>
<pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
<path d="M40 0H0V40" fill="none" stroke="#1E293B" stroke-width="1" opacity="0.5"/></pattern>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#0C1424"/><stop offset="100%" stop-color="#060910"/></linearGradient>
<filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
<feGaussianBlur stdDeviation="8" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
</defs>
<rect width="1200" height="400" fill="url(#bg)"/>
<rect width="1200" height="400" fill="url(#grid)"/>
{''.join(f'<rect x="0" y="{i * 2}" width="1200" height="2" fill="{c}" opacity="0.7"/>' for i, c in enumerate(colors))}
<text x="70" y="120" fill="#94A3B8" font-family="Consolas,Monaco,monospace" font-size="20" letter-spacing="8">A BUILD LOG IN FOUR ACTS</text>
<text x="70" y="205" fill="#F8FAFC" font-family="Segoe UI,Arial,sans-serif" font-size="66" font-weight="800">CYBERSECURITY</text>
<text x="70" y="276" fill="#F8FAFC" font-family="Segoe UI,Arial,sans-serif" font-size="66" font-weight="800">PROJECTS<tspan fill="{colors[2]}">.</tspan></text>
<text x="70" y="316" fill="#64748B" font-family="Consolas,Monaco,monospace" font-size="18">69 original builds   ·   4 tiers   ·   777 tests   ·   one repo</text>
{bars}
<g filter="url(#glow)">{rings}</g>
{nodes}
<text x="1010" y="210" fill="#E2E8F0" font-family="Segoe UI,Arial,sans-serif" font-size="34" font-weight="700" text-anchor="middle">4</text>
<text x="1010" y="238" fill="#64748B" font-family="Consolas,Monaco,monospace" font-size="13" text-anchor="middle">TIERS</text>
</svg>'''


def main() -> None:
    count = 0
    for tier in PALETTES:
        tier_dir = ROOT / tier
        if not tier_dir.exists():
            continue
        for folder in sorted(p for p in tier_dir.iterdir() if p.is_dir()):
            assets = folder / "assets"
            assets.mkdir(exist_ok=True)
            (assets / "hero.svg").write_text(banner(tier, folder.name), encoding="utf-8")
            count += 1
    root_assets = ROOT / "assets"
    root_assets.mkdir(exist_ok=True)
    (root_assets / "portfolio-hero.svg").write_text(portfolio_banner(), encoding="utf-8")
    print(f"generated {count} project banners + 1 portfolio banner")


if __name__ == "__main__":
    main()
