# Learn — 802.11 deauth flood detection

## What the frames mean

Deauthentication and disassociation frames are management frames that tear down a client's association. A single one is normal (roaming, inactivity, AP load). A burst aimed at one client, or a broad burst from one AP across many clients, is a useful defense signal.

## Grouping keys

Grouping by `(receiver, BSSID)` finds targeted floods while naturally separating simultaneous events on different access points. A second grouping by BSSID alone catches the case where an attacker spreads frames across many clients to evade a per-client threshold.

## Sliding windows

As with login brute force, a fixed wall-clock second can split a burst at its boundary. Considering each frame as a possible window start and keeping the largest cluster avoids that artifact.

## Synthetic MAC addresses

Addresses beginning with `02:` have the locally administered bit set and are conventionally safe to use in examples. The test fixtures never represent real devices.

## Exercises

- Add sequence-number gap detection to spot spoofed management frames.
- Correlate with RSSI changes to distinguish a flood from a moving client.
- Export alerts in a SIEM-friendly JSON schema with stable event IDs.
