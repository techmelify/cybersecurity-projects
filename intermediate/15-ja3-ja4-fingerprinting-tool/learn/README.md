# Learn — TLS fingerprinting basics

## What a fingerprint is

Client implementations differ in the order and set of fields they send in a TLS ClientHello. Those differences form a stable identifier that can be hashed and compared, even when the traffic is encrypted.

## JA3 construction

JA3 concatenates five fields in a fixed order: protocol version, cipher suites, extensions, elliptic curves, and EC point formats. Within each list, decimal values are separated by hyphens; the five fields are separated by commas. The resulting string is MD5-hashed.

Because cipher ordering is preserved, two clients with the same suites in a different order produce different JA3 hashes. That is intentional: ordering is itself a distinguishing trait.

## JA4-like variation

Real JA4 uses its own ordering, encoding, and SHA-256 based format. The variant in this project is deliberately simpler: sort and de-duplicate lists so that ordering noise is removed, include a count of ciphers, and truncate a SHA-256 digest. Treat it as a teaching aid rather than an interoperable implementation.

## GREASE

Browsers insert random "GREASE" values to discourage servers from relying on exact field enumerations. Real fingerprinting pipelines usually filter those values before hashing. This lab leaves the caller in control of the input list.

## Safety

Fingerprinting here operates only on numbers the caller supplies. No capture, interception, or network access is involved, and the hashes are not used to identify or track real people.
