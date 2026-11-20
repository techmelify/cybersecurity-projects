# Learn — beacon timing

## Why timing is a signal

Many command-and-control clients check in at a fixed interval with small random jitter. That produces a distinctive rhythm in connection logs. Human browsing is far less regular.

## Median absolute deviation

The mean is sensitive to outliers, so this project uses the median gap and the median absolute deviation (MAD) around it. `regularity = 1 - MAD / median` is close to 1 for consistent intervals and lower for irregular ones.

## Safety boundary

A live beacon is dual-use and needs a controlled lab. This project keeps only the educational model: generating timestamps and detecting patterns in them.
