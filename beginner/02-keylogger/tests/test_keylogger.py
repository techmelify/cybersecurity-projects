import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keylogger import KeyEvent, KeyLogger, main, run  # noqa: E402


class KeyLoggerTests(unittest.TestCase):
    def test_record_and_events(self):
        logger = KeyLogger()
        logger.start()
        logger.record("a", timestamp=1.0)
        logger.record("b", timestamp=2.0)
        logger.stop()
        self.assertEqual(logger.events, (KeyEvent("a", 1.0), KeyEvent("b", 2.0)))

    def test_must_be_running(self):
        logger = KeyLogger()
        with self.assertRaises(RuntimeError):
            logger.record("a")

    def test_empty_key_rejected(self):
        logger = KeyLogger()
        logger.start()
        with self.assertRaises(ValueError):
            logger.record("")

    def test_save_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.jsonl"
            logger = KeyLogger()
            logger.start()
            logger.record("x", timestamp=7.5)
            self.assertEqual(logger.save(path), 1)
            line = json.loads(path.read_text(encoding="utf-8").strip())
            self.assertEqual(line, {"key": "x", "timestamp": 7.5})

    def test_clear(self):
        logger = KeyLogger()
        logger.start()
        logger.record("a")
        logger.clear()
        self.assertEqual(logger.events, ())

    def test_run_with_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.jsonl"
            self.assertEqual(run(iter("abc"), path), 3)

    def test_cli_requires_confirmation(self):
        self.assertEqual(main([]), 2)
        self.assertEqual(main(["--output", "x.jsonl"]), 2)


if __name__ == "__main__":
    unittest.main()
