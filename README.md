# Cybersecurity Projects — Build Log

Original implementations of the [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects) catalog, built in tier order: Foundations → Beginner → Intermediate → Advanced.

**Status:** scaffolding. The prior portfolio workspace is still present because the local cleanup is blocked by a host-level PowerShell spawn failure. No old files have been removed yet.

## Scope

- 69 projects listed upstream (43 with reference source, 27 synopsis-only).
- Written from scratch in our own code; the upstream repo is a specification/reference, not a copy source.
- Each project gets its own folder with implementation, tests, and a short README.
- Only Python is installed on this host. Where upstream specifies another language, the project is reimplemented in Python with the deviation noted in its README.
- No real malware, no production targets, no fabricated evidence. Anything dynamic stays in an isolated lab.

## Layout

```
cybersecurity-projects/
├── README.md
├── ROADMAP.md
├── foundations/
│   └── 01-hash-identifier/
├── beginner/
├── intermediate/
└── advanced/
```

## Progress

See [ROADMAP.md](ROADMAP.md). Nothing is marked complete yet.

## Reference

- Source list: https://github.com/CarterPerez-dev/Cybersecurity-Projects
- License of the reference catalog: AGPL-3.0 (our implementations are original work).
