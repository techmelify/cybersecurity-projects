# Learn — data loss prevention heuristics

## What DLP looks for

Data loss prevention tools classify content that may contain sensitive information: contact details, government identifier shapes, payment card numbers, and API keys. They typically combine patterns with validation steps to reduce false positives.

## Why validate with a checksum

A long run of digits is not automatically a card number. The Luhn checksum is a simple arithmetic check that filters many random digit strings. Passing Luhn still does not prove a number is real, and failing it does not prove harmlessness.

## Severity tiers

Not every match has equal impact. An email address might be low severity in one context, while a national-ID-like value or an API key is high severity because it can enable identity theft or direct access.

## Redaction

Reports should avoid repeating the sensitive value. Masking the middle preserves enough structure for a human to recognise which field was found while limiting exposure in logs.

## Limits of regex heuristics

Regular expressions cannot understand context. They can miss obfuscated values and flag harmless strings that happen to fit a shape. Treat results as triage signals and keep all lab fixtures synthetic.
