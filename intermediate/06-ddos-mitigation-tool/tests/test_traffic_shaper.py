import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traffic_shaper import (  # noqa: E402
    Request,
    format_report,
    generate_requests,
    load_requests,
    main,
    simulate,
    sliding_window,
    token_bucket,
)


def burst(times, client="192.0.2.10"):
    return [Request(moment, client, "/login") for moment in times]


class TokenBucketTests(unittest.TestCase):
    def test_capacity_is_enforced(self):
        decisions = token_bucket(burst([0, 0, 0]), capacity=2, refill_per_second=0)
        self.assertEqual([d.allowed for d in decisions], [True, True, False])
        self.assertEqual(decisions[-1].reason, "bucket_empty")

    def test_tokens_refill_over_time(self):
        decisions = token_bucket(burst([0, 0.5]), capacity=1, refill_per_second=1)
        self.assertEqual([d.allowed for d in decisions], [True, False])
        refilled = token_bucket(burst([0, 1]), capacity=1, refill_per_second=1)
        self.assertEqual([d.allowed for d in refilled], [True, True])

    def test_buckets_are_per_client(self):
        requests = [Request(0, "192.0.2.10"), Request(0, "192.0.2.11")]
        decisions = token_bucket(requests, capacity=1, refill_per_second=0)
        self.assertTrue(all(decision.allowed for decision in decisions))

    def test_initial_tokens(self):
        decisions = token_bucket(burst([0]), capacity=1, refill_per_second=1, initial_tokens=0)
        self.assertFalse(decisions[0].allowed)

    def test_validation(self):
        for kwargs in (
            {"capacity": 0, "refill_per_second": 1},
            {"capacity": 1, "refill_per_second": -1},
            {"capacity": 1, "refill_per_second": 1, "initial_tokens": 2},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                token_bucket([], **kwargs)

    def test_negative_time_rejected(self):
        with self.assertRaises(ValueError):
            token_bucket(burst([-1]), capacity=1, refill_per_second=1)


class SlidingWindowTests(unittest.TestCase):
    def test_limit_and_expiry(self):
        decisions = sliding_window(burst([0, 1, 2, 3]), limit=2, window_seconds=2.5)
        self.assertEqual([d.allowed for d in decisions], [True, True, False, True])
        self.assertEqual(decisions[2].reason, "window_full")

    def test_window_boundary_is_exclusive(self):
        decisions = sliding_window(burst([0, 10]), limit=1, window_seconds=10)
        self.assertEqual([d.allowed for d in decisions], [True, True])

    def test_windows_are_per_client(self):
        requests = [Request(0, "192.0.2.10"), Request(0, "192.0.2.11")]
        decisions = sliding_window(requests, limit=1, window_seconds=60)
        self.assertTrue(all(decision.allowed for decision in decisions))

    def test_validation(self):
        with self.assertRaises(ValueError):
            sliding_window([], limit=0, window_seconds=60)
        with self.assertRaises(ValueError):
            sliding_window([], limit=1, window_seconds=0)


class SimulationTests(unittest.TestCase):
    def test_combined_blocks_on_bucket(self):
        result = simulate(burst([0, 0, 0]), capacity=1, refill_per_second=0,
                          window_limit=10, window_seconds=60)
        reasons = [decision.reason for decision in result.combined]
        self.assertEqual(reasons, ["both_allowed", "blocked_by_token_bucket", "blocked_by_token_bucket"])
        self.assertEqual((result.allowed, result.dropped), (1, 2))

    def test_combined_blocks_on_window(self):
        result = simulate(burst([0, 1, 2]), capacity=10, refill_per_second=0,
                          window_limit=1, window_seconds=60)
        reasons = [decision.reason for decision in result.combined]
        self.assertEqual(reasons[1:], ["blocked_by_sliding_window", "blocked_by_sliding_window"])

    def test_input_order_does_not_matter(self):
        requests = generate_requests(12)
        forward = simulate(requests, capacity=3, refill_per_second=2, window_limit=5, window_seconds=4)
        backward = simulate(list(reversed(requests)), capacity=3, refill_per_second=2,
                            window_limit=5, window_seconds=4)
        self.assertEqual(forward, backward)

    def test_empty_log(self):
        result = simulate([])
        self.assertEqual(result.combined, ())
        self.assertEqual((result.allowed, result.dropped), (0, 0))
        self.assertIn("none", format_report(result))

    def test_report_shape(self):
        result = simulate(burst([0, 0]), capacity=1, refill_per_second=0)
        report = format_report(result)
        self.assertIn("Requests: 2", report)
        self.assertIn("Dropped: 1", report)
        self.assertIn("DROP ", report)


class LogAndCliTests(unittest.TestCase):
    def test_generate_requests_is_deterministic(self):
        first = generate_requests(15)
        self.assertEqual(first, generate_requests(15))
        self.assertNotEqual(first, generate_requests(15, seed=99))
        self.assertEqual(len(generate_requests(0)), 0)
        with self.assertRaises(ValueError):
            generate_requests(-1)

    def test_load_requests(self):
        payload = "\n".join([
            json.dumps({"time": 0.0, "client": "192.0.2.10", "path": "/"}),
            "",
            json.dumps({"time": 0.5, "client": "192.0.2.11"}),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requests.jsonl"
            path.write_text(payload, encoding="utf-8")
            requests = load_requests(path)
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[1].path, "/")

    def test_load_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requests.jsonl"
            path.write_text("not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_requests(path)

    def test_load_missing_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requests.jsonl"
            path.write_text('{"time": 0}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_requests(path)

    def test_cli_demo_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["--demo", "--count", "6", "--json", "--capacity", "2",
                         "--rate", "1", "--window-limit", "2", "--window", "5"])
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(len(payload["combined"]), 6)
        self.assertEqual(payload["allowed"] + payload["dropped"], 6)

    def test_cli_log_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "requests.jsonl"
            path.write_text(json.dumps({"time": 0, "client": "192.0.2.10"}), encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["--log", str(path)])
            self.assertEqual(code, 0)
        self.assertIn("Traffic shaping simulation", buffer.getvalue())

    def test_cli_missing_log(self):
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as tmp, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--log", str(Path(tmp) / "none.jsonl")]), 2)


if __name__ == "__main__":
    unittest.main()
