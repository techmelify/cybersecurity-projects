# Learn — security response headers

## What these headers do

- **CSP** restricts which origins may load scripts, styles, images, and frames. It is the strongest single control here.
- **HSTS** forces HTTPS on subsequent visits. A short `max-age` gives little protection.
- **X-Content-Type-Options: nosniff** stops browsers from guessing a content type and executing non-script files as script.
- **X-Frame-Options** (or CSP `frame-ancestors`) blocks clickjacking.
- **Referrer-Policy** limits how much URL data leaks to third parties.
- **Permissions-Policy** disables powerful browser features such as camera and geolocation.
- **Server / X-Powered-By** are not vulnerabilities, but version banners help an attacker fingerprint a target.

## Why offline scanning matters

Tests must be deterministic. Parsing a saved header file means the suite never depends on DNS, a live server, or an internet connection. The same parser is used for both file and URL input.

## Design notes

- Header lookup is case-insensitive because HTTP header names are case-insensitive.
- A missing optional control is a `warn`, not a `fail`, so the score does not punish sites that use an equivalent control elsewhere.
- Score uses half-credit for warnings so partial protection is visible.
