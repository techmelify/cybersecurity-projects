# Learn — LSB steganography

## Least significant bits

In an 8-bit colour channel, changing bit 0 changes the value by at most 1 — imperceptible in most images. Using one bit per channel gives 3 bits per pixel.

## Framing

A payload needs a length so the extractor knows when to stop. A 32-bit big-endian prefix is written first, followed by the payload. Each bit is stored in the LSB of successive channel bytes.

## Capacity math

Each channel byte carries exactly 1 bit, so an image with `N` channel bytes carries `N` bits = `N/8` bytes. The 32-bit prefix costs 4 bytes, leaving `N/8 - 4` bytes. For an 8×8 RGB image, `N = 192`, so capacity is `24 - 4 = 20` bytes.

## Why PPM

PNG and JPEG require codecs and compression semantics. PPM is a plain header plus raw bytes, which makes the storage layout fully visible and the tests deterministic.

## Exercises

- Add a magic marker so random images can be rejected before length parsing.
- Add XOR encryption with a passphrase.
- Port to PNG using Pillow while keeping the same bit-writing core.
