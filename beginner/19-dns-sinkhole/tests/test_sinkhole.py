import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sinkhole import BEGIN, END, main, merge_hosts, parse_blocklist  # noqa: E402


class SinkholeTests(unittest.TestCase):
    def test_parse_blocklist(self):
        text = "ads.example.com\n# comment\n0.0.0.0 ads.example.com\n\n"
        self.assertEqual(parse_blocklist(text), ["ads.example.com"])

    def test_merge_adds_block(self):
        result = merge_hosts("127.0.0.1 localhost\n", ["ads.example.com"])
        self.assertIn(BEGIN, result.lines)
        self.assertIn("0.0.0.0 ads.example.com", result.lines)
        self.assertEqual(result.added, 1)

    def test_merge_replaces_old_block(self):
        existing = "\n".join([BEGIN, "0.0.0.0 old.example", END, "127.0.0.1 localhost"])
        result = merge_hosts(existing, ["new.example"])
        self.assertEqual(result.removed, 1)
        self.assertNotIn("old.example", "\n".join(result.lines))
        self.assertIn("0.0.0.0 new.example", result.lines)

    def test_custom_ip(self):
        result = merge_hosts("", ["x"], "127.0.0.1")
        self.assertIn("127.0.0.1 x", result.lines)

    def test_cli_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts"
            block = Path(tmp) / "block.txt"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            block.write_text("ads.example.com\n", encoding="utf-8")
            self.assertEqual(main([str(hosts), str(block)]), 0)
            self.assertNotIn(BEGIN, hosts.read_text(encoding="utf-8"))

    def test_cli_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts"
            block = Path(tmp) / "block.txt"
            block.write_text("ads.example.com\n", encoding="utf-8")
            self.assertEqual(main([str(hosts), str(block), "--apply"]), 0)
            self.assertIn(BEGIN, hosts.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
