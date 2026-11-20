# Learning notes — CNAME hygiene

## What a CNAME does

A CNAME record aliases one name to another. If the alias target is retired but
the CNAME remains, the name is "dangling". If the target belongs to a service
that lets users bind custom domains, an unused binding can be a takeover risk.

## Why this build is snapshot-only

A real scanner would resolve names and query providers, which means network
access and live targets. This project keeps the lesson defensive and
reproducible: you supply the records, the provider list, and the dangling
observations in a JSON file. The analyzer only compares strings.

## Detection ideas

- Normalize names (lowercase, drop a trailing dot) before comparing.
- Match provider domains by suffix, preferring the most specific domain.
- Treat a CNAME to a provider apex as riskier than a tenant-specific target.
- Recommend removal or re-binding of stale records; never attempt the takeover.

Review findings with the DNS owner before changing production records.
