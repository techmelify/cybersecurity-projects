import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stego import PPMImage, StegoError, capacity_bytes, hide, main, reveal  # noqa: E402


def make_image(width=8, height=8):
    pixels = bytes((i * 37 + 11) % 256 for i in range(width * height * 3))
    return PPMImage(width, height, 255, pixels)


class StegoTests(unittest.TestCase):
    def setUp(self):
        self.image = make_image()

    def test_round_trip(self):
        payload = b"hidden message"
        result = hide(self.image, payload)
        self.assertEqual(reveal(result), payload)

    def test_original_pixels_only_change_in_lsb(self):
        payload = b"abc"
        result = hide(self.image, payload)
        for before, after in zip(self.image.pixels, result.pixels):
            self.assertEqual(before & 0xFE, after & 0xFE)

    def test_capacity(self):
        self.assertEqual(capacity_bytes(self.image), 8 * 8 * 3 - 32)

    def test_oversized_payload(self):
        with self.assertRaises(StegoError):
            hide(self.image, b"x" * (capacity_bytes(self.image) + 1))

    def test_empty_payload(self):
        with self.assertRaises(StegoError):
            hide(self.image, b"")

    def test_parse_and_serialize(self):
        raw = self.image.to_bytes()
        parsed = PPMImage.from_bytes(raw)
        self.assertEqual((parsed.width, parsed.height, parsed.maxval), (8, 8, 255))
        self.assertEqual(parsed.pixels, self.image.pixels)

    def test_parse_comment(self):
        raw = b"P6\n# a comment\n8 8\n255\n" + self.image.pixels
        self.assertEqual(PPMImage.from_bytes(raw).pixels, self.image.pixels)

    def test_reject_non_p6(self):
        with self.assertRaises(StegoError):
            PPMImage.from_bytes(b"P3\n8 8\n255\n")

    def test_cli_hide_reveal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image_path = root / "cover.ppm"
            payload_path = root / "msg.txt"
            output_path = root / "stego.ppm"
            extracted_path = root / "out.txt"
            image_path.write_bytes(self.image.to_bytes())
            payload_path.write_bytes(b"cli secret")
            self.assertEqual(main(["hide", str(image_path), str(payload_path), "-o", str(output_path)]), 0)
            self.assertEqual(main(["reveal", str(output_path), "-o", str(extracted_path)]), 0)
            self.assertEqual(extracted_path.read_bytes(), b"cli secret")


if __name__ == "__main__":
    unittest.main()
