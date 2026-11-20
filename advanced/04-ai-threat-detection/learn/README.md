# Learn — transparent anomaly scoring

## Why start with z-scores

A z-score says how many standard deviations a value sits from a baseline mean.
It is cheap, inspectable, and needs no training pipeline. For a lab data set,
that makes it a better teaching tool than an opaque neural network: every alert
can be traced to a concrete feature and threshold.

## Population standard deviation

The baseline uses `sqrt(sum((x - mean)^2) / n)`, i.e. the population standard
deviation. Division by `n` rather than `n - 1` is deliberate for a fixed
descriptive baseline, not an inferential sample estimate.

## Degenerate features

If every baseline vector has the same value, the standard deviation is zero and
division is impossible. The detector returns `0` for an identical observation
and a capped `10` for any deviation, so a constant feature cannot silently
suppress or explode an alert.

## Rules plus statistics

Z-scores find unusual magnitudes; rules encode policy. A value can be normal
statistically but still forbidden (for example more than five failed logins),
so rule hits are reported independently of the z-threshold.

## What this is not

There is no learned classifier, no persisted model, no drift adaptation, and
no ground-truth labels. This is a deterministic rule-and-statistics baseline,
not a production detection system.

## Exercises

- Add a median/absolute-deviation score and compare alerts.
- Add per-feature weighting instead of using the peak z-score.
- Add a JSON schema check for event files.
