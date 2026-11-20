# Learn — firewall rule evaluation

## First match wins

Most firewalls evaluate rules top to bottom. The first matching rule applies, so ordering matters: a broad allow rule before a specific deny rule can defeat the deny.

## Default deny

A secure baseline blocks everything not explicitly allowed. This engine returns `deny` with rule `default` when no rule matches.

## Matching dimensions

Rules typically combine source, destination, port, and protocol. CIDR notation expresses subnets compactly. Port lists and ranges keep rule counts manageable.
