import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from feed_scraper import (  # noqa: E402
    FeedItem,
    format_report,
    main,
    parse_feed,
    rank_items,
    ranked_to_dict,
)

RSS = """<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Lab Security Feed</title>
    <item>
      <title>New CVE advisory published</title>
      <link>https://example.test/a</link>
      <pubDate>Wed, 18 Nov 2026 12:00:00 +0000</pubDate>
      <description>Patch for a vulnerability in a lab package.</description>
    </item>
    <item>
      <title>Conference schedule</title>
      <link>https://example.test/b</link>
      <description>Social program and catering.</description>
    </item>
  </channel>
</rss>
"""

ATOM = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Lab Atom Feed</title>
  <entry>
    <title>Ransomware breach report</title>
    <link href="https://example.test/c" rel="alternate"/>
    <published>2026-11-19T09:30:00Z</published>
    <summary>Details of a synthetic breach.</summary>
  </entry>
  <entry>
    <title>Routine update</title>
    <link href="https://example.test/d" rel="self"/>
    <updated>2026-11-01T00:00:00+00:00</updated>
  </entry>
</feed>
"""

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


def item(title, *, published=None, summary="", link="https://example.test/x"):
    return FeedItem(title, link, published, summary, "lab")


class ParseFeedTests(unittest.TestCase):
    def test_parse_rss_items(self):
        items = parse_feed(RSS)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].title, "New CVE advisory published")
        self.assertEqual(items[0].link, "https://example.test/a")
        self.assertEqual(items[0].summary, "Patch for a vulnerability in a lab package.")
        self.assertEqual(items[0].published.date().isoformat(), "2026-11-18")
        self.assertEqual(items[0].source, "Lab Security Feed")

    def test_parse_atom_with_namespace(self):
        items = parse_feed(ATOM)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].title, "Ransomware breach report")
        self.assertEqual(items[0].link, "https://example.test/c")
        self.assertEqual(items[0].source, "Lab Atom Feed")
        self.assertEqual(items[0].published.date().isoformat(), "2026-11-19")

    def test_non_alternate_atom_link_is_ignored(self):
        items = parse_feed(ATOM)
        self.assertEqual(items[1].link, "")

    def test_missing_optional_fields(self):
        xml = "<rss><channel><item><title>Bare item</title></item></channel></rss>"
        parsed = parse_feed(xml)
        self.assertEqual(parsed[0].title, "Bare item")
        self.assertIsNone(parsed[0].published)
        self.assertEqual(parsed[0].summary, "")

    def test_untitled_item_uses_placeholder(self):
        xml = "<rss><channel><item><description>No title here</description></item></channel></rss>"
        self.assertEqual(parse_feed(xml)[0].title, "(untitled)")

    def test_bad_date_does_not_crash(self):
        xml = "<rss><channel><item><title>x</title><pubDate>not-a-date</pubDate></item></channel></rss>"
        self.assertIsNone(parse_feed(xml)[0].published)

    def test_empty_feed(self):
        self.assertEqual(parse_feed("<rss><channel><title>Empty</title></channel></rss>"), [])

    def test_malformed_xml_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_feed("<rss><channel></rss>")

    def test_doctype_is_rejected(self):
        xml = '<!DOCTYPE rss [<!ENTITY x "boom">]><rss><channel/></rss>'
        with self.assertRaises(ValueError):
            parse_feed(xml)


class RankItemsTests(unittest.TestCase):
    def test_keyword_ranking(self):
        items = [
            item("Conference catering"),
            item("Critical CVE advisory", summary="Exploit and patch details"),
        ]
        ranked = rank_items(items)
        self.assertEqual(ranked[0].item.title, "Critical CVE advisory")
        self.assertGreater(ranked[0].score, ranked[1].score)
        self.assertEqual(ranked[1].score, 0.0)
        self.assertTrue(any("keyword:cve" in reason for reason in ranked[0].reasons))

    def test_recency_is_deterministic_with_explicit_now(self):
        fresh = item("Fresh", published=datetime(2026, 11, 19, tzinfo=timezone.utc))
        stale = item("Stale", published=datetime(2020, 1, 1, tzinfo=timezone.utc))
        ranked = rank_items([stale, fresh], now=NOW)
        self.assertEqual(ranked[0].item.title, "Fresh")
        self.assertGreater(ranked[0].score, ranked[1].score)

    def test_no_clock_dependency_without_now(self):
        dated = item("Dated", published=datetime(2026, 11, 19, tzinfo=timezone.utc))
        self.assertEqual(rank_items([dated])[0].score, 0.0)

    def test_custom_keywords(self):
        items = [item("Catering and coffee"), item("Breach disclosed")]
        ranked = rank_items(items, {"catering": 5.0})
        self.assertEqual(ranked[0].item.title, "Catering and coffee")

    def test_tie_break_is_stable(self):
        items = [item("zebra", link="b"), item("alpha", link="c"), item("alpha", link="a")]
        ranked = rank_items(items)
        self.assertEqual([entry.item.link for entry in ranked], ["a", "c", "b"])

    def test_invalid_half_life(self):
        with self.assertRaises(ValueError):
            rank_items([], half_life_days=0)

    def test_report_and_json_shape(self):
        ranked = rank_items(parse_feed(RSS))
        report = format_report(ranked)
        self.assertIn("New CVE advisory published", report)
        self.assertIn("Lab Security Feed", ranked_to_dict(ranked)[0]["source"])
        self.assertEqual(format_report([]), "No feed items.")


class CliTests(unittest.TestCase):
    def test_cli_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.xml"
            path.write_text(RSS, encoding="utf-8")
            result = main(["--file", str(path), "--json", "--limit", "1"])
            self.assertEqual(result, 0)

    def test_cli_text_with_now_and_custom_keywords(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.xml"
            path.write_text(ATOM, encoding="utf-8")
            result = main([
                "--file", str(path),
                "--now", "2026-11-20T00:00:00Z",
                "--keywords", "ransomware=4", "breach=2",
            ])
            self.assertEqual(result, 0)

    def test_cli_missing_file_exits_cleanly(self):
        from contextlib import redirect_stderr
        import io

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--file", str(Path(tmp) / "missing.xml")]), 2)

    def test_cli_bad_keyword_exits_cleanly(self):
        from contextlib import redirect_stderr
        import io

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            path = Path(tmp) / "feed.xml"
            path.write_text(RSS, encoding="utf-8")
            self.assertEqual(main(["--file", str(path), "--keywords", "oops"]), 2)

    def test_json_output_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.xml"
            path.write_text(RSS, encoding="utf-8")
            import io
            from contextlib import redirect_stdout

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main(["--file", str(path), "--json"])
            payload = json.loads(buffer.getvalue())
            self.assertEqual(len(payload), 2)
            self.assertIn("score", payload[0])


if __name__ == "__main__":
    unittest.main()
