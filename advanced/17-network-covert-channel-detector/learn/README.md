# Learn — covert-channel detection ideas

## What is a covert channel?

A covert channel hides information in a property that was not meant to carry data, such as packet spacing or packet length.Defensive detection looks for the statistical shape of that hiding rather than trying to decode the message.

## Three simple shapes

1. **Regular timing** — an encoder that maps bits to delays often produces inter-arrival gaps with very low variation. The mean absolute deviation divided by the mean gap captures that stability. Using deviations from the mean (not the median) also avoids treating alternating bimodal gaps as perfectly regular.
2. **Size alphabet** — if sizes cluster into a handful of recurring values, they may be acting as symbols. Shannon entropy of the size distribution measures how constrained that alphabet is.
3. **Low-rate bursts** — bursts separated by long silence can avoid volume-based alerts while still moving a few symbols at a time.

## Why only analyse

Detection needs no transmitter. A defensive tool can run over exported logs, stay deterministic, and avoid creating the traffic it is looking for. It also avoids the ethical problem of building a working sender.

## False positives

Heartbeats, polling loops, and batch synchronisation can look similar. Always combine a score with asset knowledge and a human review rather than treating it as conclusive evidence.
