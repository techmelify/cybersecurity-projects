import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adversarial_detector import (  # noqa: E402
    BatchReport,
    FeatureVector,
    analyze_batch,
    analyze_vector,
    build_baseline,
    load_vectors,
    main,
)

BASELINE_DATA = [
    {"id": "b1", "values": [0.10, 0.80, 0.30, 0.60]},
    {"id": "b2", "values": [0.20, 0.70, 0.40, 0.50]},
    {"id": "b3", "values": [0.15, 0.75, 0.35, 0.55]},
    {"id": "b4", "values": [0.25, 0.65, 0.45, 0.45]},
    {"id": "b5", "values": [0.18, 0.72, 0.38, 0.52]},
    {"id": "b6", "values": [0.22, "0.68", 0.42, 0.48]},
]


def baseline():
    return build_baseline(load_vectors(BASELINE_DATA))


class AdversarialDetectorTests(unittest.TestCase):
    def test_load_vectors_accepts_both_key_styles(self):
        vectors = load_vectors([{"identifier": "x", "features": [1, 2]}])
        self.assertEqual(vectors, (FeatureVector("x", (1.0, 2.0)),))

    def test_baseline_is_deterministic(self):
        first = baseline()
        self.assertEqual(first, baseline())
        self.assertEqual(first.dimensions, 4)
        self.assertEqual(first.size, 6)
        self.assertAlmostEqual(first.means[2], 0.383333, places=5)

    def test_clean_vector_has_no_detections(self):
        vector = FeatureVector("clean", (0.18, 0.72, 0.38, 0.52))
        self.assertEqual(analyze_vector(vector, baseline()), ())

    def test_z_score_outlier_and_range(self):
        vector = FeatureVector("extreme", (5.0, 0.72, 0.38, 0.52))
        signals = {item.signal for item in analyze_vector(vector, baseline())}
        self.assertIn("z-score-outlier", signals)
        self.assertIn("out-of-range-feature", signals)

    def test_saturation(self):
        vector = FeatureVector("clipped", (0.0, 1.0, 0.0, 1.0))
        signals = {item.signal for item in analyze_vector(vector, baseline())}
        self.assertIn("saturated-features", signals)

    def test_coordinated_small_perturbation(self):
        base = baseline()
        shifted = tuple(mean + 0.10 for mean in base.means)
        vector = FeatureVector("perturbed", shifted)
        signals = {item.signal for item in analyze_vector(vector, base)}
        self.assertIn("coordinated-small-perturbation", signals)
        self.assertNotIn("z-score-outlier", signals)

    def test_batch_drift(self):
        vectors = tuple(
            FeatureVector(f"drift-{index}", (0.18, 0.72, 0.80, 0.52))
            for index in range(6)
        )
        report = analyze_batch(vectors, baseline())
        self.assertTrue(report.drift)
        self.assertEqual(report.drift[0].feature, 2)
        self.assertEqual(report.verdict, "likely-adversarial")

    def test_clean_batch_verdict(self):
        vectors = load_vectors(BASELINE_DATA)
        report = analyze_batch(vectors, baseline())
        self.assertEqual(report.verdict, "benign")
        self.assertEqual(report.score, 0)
        self.assertIsInstance(report, BatchReport)

    def test_validation_errors(self):
        with self.assertRaises(ValueError):
            build_baseline([])
        with self.assertRaises(ValueError):
            build_baseline([FeatureVector("a", (1.0,)), FeatureVector("b", (1.0, 2.0))])
        with self.assertRaises(ValueError):
            analyze_vector(FeatureVector("short", (1.0,)), baseline())
        with self.assertRaises(ValueError):
            load_vectors([{"id": "bad"}])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline_path = Path(tmp) / "baseline.json"
            input_path = Path(tmp) / "input.json"
            baseline_path.write_text(json.dumps(BASELINE_DATA), encoding="utf-8")
            input_path.write_text(
                json.dumps([{"id": "x", "values": [0.18, 0.72, 0.38, 0.52]}]),
                encoding="utf-8",
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                result = main(["--baseline", str(baseline_path), "--input", str(input_path)])
            self.assertEqual(result, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["verdict"], "benign")


if __name__ == "__main__":
    unittest.main()
