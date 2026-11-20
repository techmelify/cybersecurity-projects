import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from password_lab_simulator import (  # noqa: E402
    assign_chunks,
    build_simulation_report,
    build_synthetic_dictionary,
    estimate_work,
    main,
    partition_workload,
    simulate_chunk,
)


class PasswordLabSimulatorTests(unittest.TestCase):
    def test_dictionary_is_deterministic(self):
        self.assertEqual(
            build_synthetic_dictionary(10, 7),
            build_synthetic_dictionary(10, 7),
        )

    def test_different_seeds_change_candidates(self):
        self.assertNotEqual(
            build_synthetic_dictionary(10, 7),
            build_synthetic_dictionary(10, 8),
        )

    def test_candidates_are_synthetic_and_unique(self):
        candidates = build_synthetic_dictionary(50, 3)
        self.assertTrue(all(candidate.startswith("lab-") for candidate in candidates))
        self.assertEqual(len(candidates), len(set(candidates)))

    def test_partition_covers_all_items_once(self):
        items = tuple(str(index) for index in range(23))
        chunks = partition_workload(items, 5)
        flattened = tuple(candidate for chunk in chunks for candidate in chunk.candidates)
        self.assertEqual(flattened, items)
        self.assertEqual([chunk.size for chunk in chunks], [5, 5, 5, 5, 3])

    def test_partition_rejects_invalid_chunk_size(self):
        with self.assertRaises(ValueError):
            partition_workload(("a",), 0)

    def test_assignments_are_round_robin(self):
        chunks = partition_workload(tuple(str(index) for index in range(16)), 3)
        assignments = assign_chunks(chunks, 3)
        self.assertEqual(
            [assignment.chunk_indexes for assignment in assignments],
            [(0, 3), (1, 4), (2, 5)],
        )
        self.assertEqual(sum(len(a.chunk_indexes) for a in assignments), len(chunks))

    def test_assignments_reject_invalid_worker_count(self):
        with self.assertRaises(ValueError):
            assign_chunks((), 0)

    def test_estimate_digest_operations(self):
        chunks = partition_workload(build_synthetic_dictionary(12, 1), 4)
        assignments = assign_chunks(chunks, 2)
        estimate = estimate_work(chunks, assignments, "sha256", 3)
        self.assertEqual(estimate.candidate_count, 12)
        self.assertEqual(estimate.digest_operations, 36)
        self.assertEqual(estimate.digest_size_bytes, 32)
        self.assertEqual(estimate.chunk_count, 3)
        self.assertEqual(estimate.worker_count, 2)

    def test_estimate_counts_utf8_bytes(self):
        chunks = partition_workload(("abc", "é"), 5)
        assignments = assign_chunks(chunks, 1)
        estimate = estimate_work(chunks, assignments)
        self.assertEqual(estimate.bytes_hashed, 5)

    def test_unsupported_algorithm_rejected(self):
        with self.assertRaises(ValueError):
            estimate_work((), (), "not-a-digest")

    def test_simulate_chunk_does_not_compare_to_target(self):
        chunk = partition_workload(build_synthetic_dictionary(4, 9), 2)[0]
        simulation = simulate_chunk(chunk, "sha256")
        self.assertEqual(simulation.digest_operations, 2)
        self.assertEqual(len(simulation.first_digest_preview), 64)
        self.assertFalse(hasattr(simulation, "target_hash"))

    def test_report_to_dict_shape(self):
        report = build_simulation_report(6, 2, 3, 2, "sha256", 2)
        payload = report.to_dict()
        self.assertEqual(payload["seed"], 2)
        self.assertIn("Simulation only", payload["note"])
        self.assertEqual(payload["estimate"]["digest_operations"], 12)
        self.assertEqual(len(payload["chunks"]), 2)
        self.assertEqual(len(payload["assignments"]), 2)

    def test_cli_json_output(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main([
                "--size",
                "8",
                "--seed",
                "4",
                "--chunk-size",
                "4",
                "--workers",
                "2",
                "--json",
            ])
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["estimate"]["candidate_count"], 8)
        self.assertEqual(payload["estimate"]["worker_count"], 2)

    def test_cli_text_output_contains_simulation_notice(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(["--size", "4", "--seed", "1"])
        self.assertEqual(code, 0)
        self.assertIn("Simulation only", stdout.getvalue())

    def test_cli_rejects_zero_chunk_size(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                main(["--chunk-size", "0"])
        self.assertIn("at least 1", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
