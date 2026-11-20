# 08 — Steganography Multi-Tool (Python substitution)

Upstream specifies Go; this build uses Python. Hides text in the least significant bit (LSB) of uncompressed P6 PPM images.

## Run

```powershell
python stego.py hide cover.ppm secret.txt -o stego.ppm
python stego.py reveal stego.ppm
python stego.py reveal stego.ppm -o recovered.txt
```

## Format

- 32-bit big-endian length prefix, then raw payload bytes.
- One payload bit per RGB channel byte, MSB first.
- Only the LSB of each channel changes, so visual impact is negligible.
- Capacity is `width * height * 3 - 32` bytes.

## Test

```powershell
python -m unittest discover -s tests -v
```

9 tests, standard library only. Tests generate PPM images in memory.

## Scope

Supports 8-bit binary PPM (P6) only. No PNG/JPEG codecs, no compression, no encryption. For real images, convert to PPM first. Do not use steganography to exfiltrate data from systems you do not own.
