# Learn — typosquatting and quishing

## Homographs

Unicode contains lookalike characters: Cyrillic `а` and Latin `a` render nearly identically but are different code points. Internationalised domain names encode these with punycode (`xn--`). Normalising to a common ASCII form exposes the trick.

## Edit distance

Levenshtein distance counts insertions, deletions, and substitutions. A domain one edit away from a brand (`examp1e`) is a classic typo trap. The check is limited to a small distance to avoid false positives.

## Quishing

QR codes hide the destination URL until scanned. Defensive scanning inspects the decoded payload before a browser opens it. Shorteners, raw IPs, and `http://` are common red flags because they obscure or weaken the destination.

## Limits

Heuristics produce false positives and negatives. A convincing phishing domain can score zero if it uses an unrelated name. Combine this tool with user training and browser/email protections.
