# Learn — prompt injection

## The attack surface

LLMs receive instructions and untrusted content in the same channel. A document, email, or web page can contain text like "ignore previous instructions" that the model may treat as a command.

## Defence in depth

- Delimit untrusted content clearly and treat it as data.
- Give the model a narrow system prompt and tool permissions.
- Validate tool calls independently of the model.
- Use a pre-filter like this one to flag obvious attacks.

## Why heuristics still help

A deterministic filter is cheap, explainable, and auditable. Even though attackers can rephrase, common payloads repeat. Scoring multiple indicators avoids blocking on a single harmless phrase.
