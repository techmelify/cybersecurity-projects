# Learn — reverse-proxy route evaluation

## What a route evaluator does

A reverse proxy sits in front of backend services and decides where each request should go. The decision step can be separated from traffic forwarding: given a request description and an ordered rule list, return an upstream target or a deny. This project implements only that decision step.

## Match dimensions

- **Host** routes by the requested hostname, often used for virtual hosting.
- **Path** routes by URL prefix. Segment boundaries matter: `/api` should not accidentally capture `/apixel`.
- **Method** separates read and write traffic, allowing stricter rules for `POST`, `PUT`, or `DELETE`.
- **Headers** can carry tenant identifiers, feature flags, or internal markers. Header names are case-insensitive in HTTP.

## First match and default deny

Ordered rule lists make ordering part of the security policy. A broad allow rule placed before a specific deny rule can shadow the deny. A secure evaluator finishes with an implicit default deny so unmatched requests never reach a backend.

## Why keep it offline?

Rule evaluation is deterministic and easy to test without a network. A pure function from `(request, routes)` to a decision can be unit tested exhaustively, then reused by any transport layer. This build intentionally stops at the pure decision layer.
