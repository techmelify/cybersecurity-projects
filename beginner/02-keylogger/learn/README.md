# Learn — event handling and consent

## Event sources

A keystroke recorder has two independent parts: something that produces events and something that stores them. Keeping those separate means the storage logic is testable with synthetic data and the source can be swapped deliberately.

## Timestamps

`time.time()` gives wall-clock seconds. For real forensic work you would use a monotonic or high-resolution clock and record UTC explicitly; this project keeps the simpler form to stay readable.

## JSON Lines

One JSON object per line is easy to append, stream, and parse. It avoids loading a whole log into memory and is a common format for event data.

## Ethics

Capability is not permission. A keylogger on a machine you do not own, or on someone else's account without informed consent, is illegal in most jurisdictions. This project intentionally omits the parts that would make misuse easy: no hook installation, no autostart, no hiding, no remote delivery.
