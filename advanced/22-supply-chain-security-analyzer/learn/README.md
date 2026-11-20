# Learn — supply-chain policy checks

## SBOM snapshots

A software bill of materials lists the components in a build along with metadata such as version, publisher, license, hashes, and provenance. Analyzing a static snapshot is an offline control: it can be checked in CI or during review without fetching anything.

## Provenance

Provenance is evidence of how and where an artifact was built. A missing attestation is a gap, not proof of compromise. The check is a policy signal that invites follow-up.

## Integrity hashes

Hashes detect accidental corruption and tampering. Legacy algorithms such as MD5 and SHA-1 are considered weak because collisions are practical. A modern SHA-256 or SHA-512 digest must also have the expected hexadecimal length; a short or malformed value is not useful integrity evidence.

## Publishers and licenses

An allowlist of trusted publishers makes unexpected ownership visible. A publisher labeled `unknown` or `anonymous` deserves extra attention. License checks flag missing license data and licenses that conflict with distribution policy, such as AGPL-3.0 or SSPL-1.0 in a restrictive deployment.

## Deterministic policy output

Sorting findings by severity, category, and component makes reports diffable across runs. That is useful for tracking whether a dependency update fixed one issue without introducing another.
