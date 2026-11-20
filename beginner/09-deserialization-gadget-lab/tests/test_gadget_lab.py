import pickle
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gadget_lab  # noqa: E402
from gadget_lab import UnsafeGadget, make_lab_payload, safe_loads, unsafe_loads  # noqa: E402


class GadgetLabTests(unittest.TestCase):
    def test_plain_data_round_trip(self):
        data = pickle.dumps({"a": [1, 2, 3]})
        self.assertEqual(safe_loads(data), {"a": [1, 2, 3]})

    def test_unsafe_load_executes_harmless_gadget(self):
        self.assertEqual(unsafe_loads(make_lab_payload("test")), "MARKER::test")

    def test_safe_load_blocks_gadget(self):
        with self.assertRaises(UnsafeGadget):
            safe_loads(make_lab_payload(), frozenset())

    def test_safe_load_allows_explicit_module(self):
        result = safe_loads(make_lab_payload("ok"), frozenset({"gadget_lab"}))
        self.assertEqual(result, "MARKER::ok")

    def test_cli_payload_and_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.bin"
            path.write_bytes(make_lab_payload())
            self.assertEqual(gadget_lab.main(["check", str(path)]), 1)
            self.assertEqual(gadget_lab.main(["check", str(path), "--allow-main"]), 1)


if __name__ == "__main__":
    unittest.main()
