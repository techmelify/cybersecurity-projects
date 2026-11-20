import contextlib
import io
import json
import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rate_limiter import (  # noqa: E402
    Request,
    SlidingWindowConfig,
    TokenBucketConfig,
    evaluate_sliding_window,
    evaluate_token_bucket,
    generate_requests,
    main,
)


class RateLimiterTests(unittest.TestCase):
    def test_generate_requests_is_deterministic(self):
        first = generate_requests(4, start=1.5, interval=0.5)
        second = generate_requests(4, start=1.5, interval=0.5)
        self.assertEqual(first, second)
        self.assertEqual([r.timestamp for r in first], [1.5, 2.0, 2.5, 3.0])
        self.assertEqual(first[0].request_id, "req-000")

    def test_request_rejects_non_finite_timestamp(self):
        with self.assertRaises(ValueError):
            Request("bad", math.inf)

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            TokenBucketConfig(0, 1)
        with self.assertRaises(ValueError):
            TokenBucketConfig(1, -1)
        with self.assertRaises(ValueError):
            SlidingWindowConfig(0, 5)
        with self.assertRaises(ValueError):
            SlidingWindowConfig(1, 0)

    def test_token_bucket_allows_initial_burst(self):
        requests = generate_requests(3, interval=0)
        outcome = evaluate_token_bucket(requests, TokenBucketConfig(2, 1))
        self.assertEqual([d.allowed for d in outcome.decisions], [True, True, False])
        self.assertEqual((outcome.allowed, outcome.dropped), (2, 1))

    def test_token_bucket_refills_over_synthetic_time(self):
        requests = (
            Request("a", 0.0),
            Request("b", 0.5),
            Request("c", 1.5),
        )
        outcome = evaluate_token_bucket(requests, TokenBucketConfig(1, 1))
        self.assertEqual([d.allowed for d in outcome.decisions], [True, False, True])
        self.assertAlmostEqual(outcome.decisions[-1].remaining, 0.0)

    def test_token_bucket_stable_order_for_equal_timestamps(self):
        requests = tuple(Request(name, 0.0) for name in ("z", "a", "m"))
        outcome = evaluate_token_bucket(requests, TokenBucketConfig(1, 0))
        self.assertEqual([d.request_id for d in outcome.decisions], ["z", "a", "m"])
        self.assertEqual([d.allowed for d in outcome.decisions], [True, False, False])

    def test_sliding_window_boundary_expiry(self):
        requests = (Request("a", 0), Request("b", 1), Request("c", 9), Request("d", 10))
        outcome = evaluate_sliding_window(requests, SlidingWindowConfig(2, 10))
        self.assertEqual([d.allowed for d in outcome.decisions], [True, True, False, True])

    def test_sliding_window_drops_do_not_consume_slots(self):
        requests = generate_requests(3, start=0, interval=1)
        outcome = evaluate_sliding_window(requests, SlidingWindowConfig(1, 10))
        self.assertEqual([d.allowed for d in outcome.decisions], [True, False, False])

    def test_outcome_counts_match_decisions(self):
        requests = generate_requests(9, interval=0.2)
        for outcome in (
            evaluate_token_bucket(requests, TokenBucketConfig(2, 1.5)),
            evaluate_sliding_window(requests, SlidingWindowConfig(4, 1)),
        ):
            self.assertEqual(outcome.allowed + outcome.dropped, len(requests))

    def test_cli_json_report(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--generate", "5", "--capacity", "2", "--refill-rate", "0", "--json"])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["token_bucket"]["allowed"], 2)
        self.assertEqual(report["sliding_window"]["dropped"], 2)
        self.assertEqual(len(report["token_bucket"]["decisions"]), 5)

    def test_cli_rejects_bad_input(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = main(["--timestamps", "0,not-a-number"])
        self.assertEqual(code, 1)
        self.assertIn("error", output.getvalue())


if __name__ == "__main__":
    unittest.main()
