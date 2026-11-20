# Learn — secret detection

## Shape first, entropy second

Specific regular expressions give high-confidence hits with a clear label. Entropy is the fallback for generated tokens that match no known vendor prefix. Shannon entropy measures how evenly characters are distributed: English words score low, random base64-ish strings score high.

Entropy alone produces false positives (hashes, compressed blobs, base64 images), so this scanner also requires a minimum length and both letters and digits.

## Why snapshots?

Scanners are often embedded in CI where the file set is already known. Accepting `dict[str, str]` makes the core a pure function: tests are deterministic, and the I/O layer stays a thin CLI that reads local files.

## Suppression as a contract

An allowlist marker is an explicit, reviewable statement that a value is not a secret. Line-level suppression prevents one false positive from hiding the rest of a file; file-level suppression is intentionally limited to a marker near the top.

## Exercises

- Add provider-specific patterns (GitHub, Slack, Stripe) with distinct rule IDs.
- Add a `--baseline` file so known test fixtures can be ignored globally.
- Compute per-rule precision against a labeled synthetic corpus.
