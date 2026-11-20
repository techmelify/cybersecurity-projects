# Learn — honeypot signals and defensive analysis

## What a honeypot is

A honeypot is a deliberately instrumented decoy service. Its value is in observing interaction patterns, not in serving real users. In a learning project, the capture can be generated synthetically so no service is exposed to the internet.

## Scanning signal

Port scanning often appears as one source touching many distinct ports in a short time. The detector uses a sliding window over `connect` events, counting distinct destination ports per source. A window keeps slow, legitimate-looking traffic from being conflated with a burst.

## Credential-stuffing signal

Credential stuffing uses many account names with a small set of reused password material. Since no real secrets are used here, the analyzer looks at the count of distinct synthetic usernames and the ratio of successful to failed authentication events. High username diversity plus very few successes is the pattern of interest.

## Repeated sources and documentation ranges

A source generating many events deserves review even if no single pattern fires. Example IP ranges reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) keep samples clearly synthetic and safe to share.

## Why thresholds matter

Thresholds turn vague suspicion into testable rules. Raising them reduces false positives but can miss slow activity; lowering them increases noise. Keeping thresholds configurable makes that trade-off explicit.
