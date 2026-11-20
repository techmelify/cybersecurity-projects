# Learn — trojan indicators

## What makes a trojan suspicious

A trojan appears useful but performs hidden actions. Static analysis looks for combinations: code that downloads or decodes something, executes it, and arranges persistence. Any one signal is common in legitimate software; the combination is what matters.

## Why only build a detector

A builder is dual-use with almost no defensive value in a learning portfolio. A detector teaches the same indicators from the blue-team side and can be applied to real artifacts safely.

## Limitations

Text pattern matching is easy to evade and produces false positives. Real malware analysis uses sandboxing, disassembly, and behavioural telemetry. This project is an introduction to indicator thinking, not a full AV engine.
