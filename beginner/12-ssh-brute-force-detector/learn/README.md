# Learn — brute-force detection

## Signals

A single failed login is normal. Many failures from one IP in a short window, especially across multiple usernames, is not. A success shortly after the cluster is a high-priority escalation.

## Sliding windows

A fixed calendar minute would split an attack that crosses a boundary. A sliding window considers every failure as a potential start and keeps the largest cluster inside the interval.

## Why offline parsing

Real auth logs contain personal data and live on systems you may not be allowed to probe. Accepting an iterable of strings means the detector is testable with synthetic data and can later be connected to a log shipper without changing the core.

## Exercises

- Add GeoIP and ASN enrichment.
- Detect distributed brute force across many IPs targeting one account.
- Export alerts as JSON for a SIEM.
