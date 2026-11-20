# Learn — DNS lookup

## Record types

- **A** maps a name to an IPv4 address.
- **AAAA** maps a name to an IPv6 address.
- **PTR** maps an IP address back to a name (reverse DNS).
- **WHOIS** is not DNS at all; it is a separate text protocol on port 43.

## Why inject resolvers

`socket.getaddrinfo` and `socket.gethostbyaddr` depend on the host's network and resolver configuration. A test that calls them would be flaky. Passing lookup functions into `DnsResolver` makes every result deterministic while the CLI wires in the real implementations.

## Deduplication

DNS answers frequently contain duplicate addresses. `sorted(set(...))` gives stable, readable output.

## Exercises

- Add MX and TXT queries using `dnspython`.
- Cache answers with a TTL.
- Parse IANA referrals and follow them to the registrar WHOIS server.
