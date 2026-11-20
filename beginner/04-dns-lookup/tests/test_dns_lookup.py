import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dns_lookup import DnsResolver, LookupResult, make_default_resolver, main  # noqa: E402


def fake_resolver() -> DnsResolver:
    return DnsResolver(
        a=lambda h: ["93.184.216.34", "93.184.216.34"],
        aaaa=lambda h: ["2606:2800:220:1:248:1893:25c8:1946"],
        ptr=lambda ip: ["example.test"],
        whois=lambda d: ["domain: EXAMPLE.TEST", "status: ACTIVE"],
    )


class DnsLookupTests(unittest.TestCase):
    def setUp(self):
        self.resolver = fake_resolver()

    def test_forward_deduplicates(self):
        self.assertEqual(self.resolver.forward("example.test").values, ("93.184.216.34",))

    def test_ipv6(self):
        self.assertEqual(len(self.resolver.ipv6("example.test").values), 1)

    def test_reverse(self):
        self.assertEqual(self.resolver.reverse("93.184.216.34").values, ("example.test",))

    def test_whois(self):
        self.assertEqual(self.resolver.whois("example.test").values[0], "domain: EXAMPLE.TEST")

    def test_render_empty(self):
        self.assertIn("(none)", LookupResult("x", "A", ()).render())

    def test_default_resolver_wiring(self):
        resolver = make_default_resolver()
        self.assertIsInstance(resolver, DnsResolver)
        self.assertTrue(callable(resolver.forward))

    def test_cli_a(self):
        self.assertEqual(main(["a", "localhost"]), 0)

    def test_cli_ptr(self):
        self.assertEqual(main(["ptr", "127.0.0.1"]), 0)


if __name__ == "__main__":
    unittest.main()
