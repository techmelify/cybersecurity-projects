# Learn — adversarial-input detection without a model

## What changes in an adversarial input?

A crafted input often looks normal to a human but sits slightly outside the distribution the system was built for. Common traces include extreme feature values, features clipped to their bounds, and many tiny coordinated shifts. A group of such inputs also moves the batch mean away from the clean baseline.

## Deterministic statistics

- **Mean and population standard deviation** describe each feature on benign data. A z-score measures how far a new value is in standard-deviation units.
- **Observed range** catches values far outside anything seen during baseline construction.
- **Saturation** counts exact boundary values, common when an optimizer clips inputs to valid limits.
- **Coordinated drift** looks for every feature moving by a small amount in the same direction.
- **Batch drift** uses the standard error (`stdev / sqrt(n)`) to decide whether a group mean has moved meaningfully.

## Why stay defensive

A detector needs no access to the target model. That makes it portable, auditable, and safe to run on logs. It cannot prove an input is benign, but it can prioritise which inputs a human should review.
