# Learning notes — GraphQL query risk

## Why depth matters

GraphQL lets clients choose nested selections. A deeply nested query can make a
server do much more work than its size suggests. Depth limits and query-cost
limits are common server-side controls.

## Other indicators

- **Introspection**: `__schema` and `__type` expose the schema. Useful in development, often restricted in production.
- **Aliases**: many aliases for the same field can multiply work while looking like one query.
- **Batching**: several operations in one request can amplify cost.
- **Missing policy**: an analyzer cannot observe live settings, so the snapshot declares them and the tool flags absent or loose limits.

## How this analyzer works

A standard-library tokenizer separates names, punctuation, numbers, and strings.
A small structural parser walks selection sets, records maximum brace depth,
counts `alias: field` patterns, and notes introspection names. It avoids false
positives from colons inside arguments or variable definitions.

All findings are defensive recommendations. No query is executed.
