# Learn — password cracking fundamentals

## Dictionary vs brute force

A dictionary attack tries likely strings first, so it finds common passwords quickly. Brute force enumerates every combination up to a bound; its cost grows as `charset_length ^ max_length`.

## Why unsalted digests are weak

Fast unsalted hashes (`MD5`, `SHA-1`, `SHA-2`) let an attacker compute billions of guesses per second on commodity GPUs. Identical passwords produce identical hashes, revealing reuse. Salted, memory-hard KDFs (bcrypt, Argon2id) exist to make exactly this attack impractical.

## Design notes

- Targets are lowercased because hex digests are case-insensitive.
- The search stops at the first match and reports how many attempts it took.
- Brute force requires an explicit maximum length so a test can never run forever.
