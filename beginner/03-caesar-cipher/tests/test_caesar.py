import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from caesar import brute_force, main, score_english, shift_text  # noqa: E402


class CaesarTests(unittest.TestCase):
    def test_encode(self):
        self.assertEqual(shift_text("abc", 3), "def")

    def test_decode(self):
        self.assertEqual(shift_text("def", 3, decode=True), "abc")

    def test_wraparound(self):
        self.assertEqual(shift_text("xyz", 3), "abc")
        self.assertEqual(shift_text("abc", -1), "zab")

    def test_case_preserved(self):
        self.assertEqual(shift_text("AbC", 1), "BcD")

    def test_non_alpha_passthrough(self):
        self.assertEqual(shift_text("a b-1!", 1), "b c-1!")

    def test_large_shift(self):
        self.assertEqual(shift_text("a", 27), "b")

    def test_round_trip(self):
        text = "Attack at dawn!"
        self.assertEqual(shift_text(shift_text(text, 17), 17, decode=True), text)

    def test_score_prefers_english(self):
        self.assertGreater(score_english("the quick brown fox"), score_english("qwh xlipk ymuqk gzm"))

    def test_score_empty(self):
        self.assertEqual(score_english("123!"), 0.0)

    def test_brute_force_finds_shift(self):
        cipher = shift_text("the attack begins at dawn", 11)
        self.assertEqual(brute_force(cipher)[0].shift, 11)

    def test_brute_force_returns_26(self):
        self.assertEqual(len(brute_force("hello")), 26)

    def test_cli_encode_decode(self):
        self.assertEqual(main(["encode", "abc", "-s", "1"]), 0)
        self.assertEqual(main(["decode", "bcd", "-s", "1"]), 0)
        self.assertEqual(main(["crack", "khoor", "-n", "3"]), 0)


if __name__ == "__main__":
    unittest.main()
