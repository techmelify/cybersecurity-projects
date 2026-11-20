import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import fields
from pathlib import Path

from cryptography.exceptions import InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hsm_emulator import HSM, Signature, WrappedKey, main  # noqa: E402


class HSMEmulatorTests(unittest.TestCase):
    def test_wrapper_has_no_plaintext_field(self):
        names = {item.name for item in fields(WrappedKey)} | {item.name for item in fields(Signature)}
        self.assertNotIn("plaintext", names)
        self.assertNotIn("key_bytes", names)
        wrapped = HSM().generate_key("alpha")
        self.assertIsInstance(wrapped, WrappedKey)

    def test_wrapping_is_deterministic_for_a_master_key(self):
        first = HSM().generate_key("alpha").to_dict()
        second = HSM().generate_key("alpha").to_dict()
        self.assertEqual(first, second)
        other = HSM(b"K" * 32).generate_key("alpha").to_dict()
        self.assertNotEqual(first["ciphertext"], other["ciphertext"])

    def test_serialization_leaks_no_key_bytes(self):
        hsm = HSM()
        wrapped = hsm.generate_key("alpha")
        payload = wrapped.to_dict()
        self.assertEqual(set(payload.values()) - {payload["key_id"], payload["algorithm"]},
                         {payload["nonce"], payload["ciphertext"], payload["tag"]})
        serialized = json.dumps(payload)
        self.assertNotIn(hsm.fingerprint("alpha"), serialized)
        self.assertNotIn(hsm.master_fingerprint(), serialized)
        for value in (payload["nonce"], payload["ciphertext"], payload["tag"]):
            self.assertEqual(bytes.fromhex(str(value)).hex(), value)

    def test_sign_and_verify(self):
        hsm = HSM()
        hsm.generate_key("alpha")
        signature = hsm.sign("alpha", b"hello")
        self.assertIsInstance(signature, Signature)
        self.assertTrue(hsm.verify("alpha", b"hello", signature))
        self.assertTrue(hsm.verify("alpha", b"hello", signature.signature))
        self.assertFalse(hsm.verify("alpha", b"different", signature))

    def test_tampered_wrapper_is_rejected(self):
        hsm = HSM()
        wrapped = hsm.generate_key("alpha")
        tampered = WrappedKey(
            wrapped.key_id,
            wrapped.nonce,
            bytes([wrapped.ciphertext[0] ^ 1]) + wrapped.ciphertext[1:],
            wrapped.tag,
        )
        with self.assertRaises(InvalidTag):
            HSM().restore_key(tampered)

    def test_restore_does_not_return_plaintext(self):
        original = HSM()
        wrapped = original.generate_key("alpha")
        restored = HSM()
        result = restored.restore_key(wrapped)
        self.assertEqual(result, "alpha")
        self.assertEqual(restored.list_key_ids(), ("alpha",))
        self.assertEqual(restored.fingerprint("alpha"), original.fingerprint("alpha"))
        self.assertTrue(restored.verify("alpha", b"msg", original.sign("alpha", b"msg")))

    def test_unknown_key_and_bad_inputs(self):
        hsm = HSM()
        with self.assertRaises(KeyError):
            hsm.sign("missing", b"x")
        with self.assertRaises(KeyError):
            hsm.verify("missing", b"x", b"\x00" * 32)
        with self.assertRaises(ValueError):
            HSM(b"short")
        with self.assertRaises(ValueError):
            hsm.generate_key("")
        with self.assertRaises(ValueError):
            hsm.generate_key("alpha", 8)
        with self.assertRaises(ValueError):
            WrappedKey.from_dict({"key_id": "x", "nonce": "zz", "ciphertext": "", "tag": ""})

    def test_fingerprints_are_one_way(self):
        hsm = HSM()
        wrapped = hsm.generate_key("alpha")
        fingerprint = hsm.fingerprint("alpha")
        self.assertEqual(len(fingerprint), 64)
        self.assertNotEqual(fingerprint, wrapped.ciphertext.hex())
        self.assertNotEqual(fingerprint, wrapped.tag.hex())

    def test_roundtrip_serialization(self):
        wrapped = HSM().generate_key("alpha")
        self.assertEqual(WrappedKey.from_dict(json.loads(json.dumps(wrapped.to_dict()))), wrapped)

    def test_cli_generate_sign_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrapper_path = Path(tmp) / "wrapped.json"

            def run(*args: str) -> dict[str, object]:
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    self.assertEqual(main(list(args)), 0)
                return json.loads(buffer.getvalue())

            payload = run("generate", "--key-id", "alpha", "--out", str(wrapper_path))
            self.assertEqual(payload["key_id"], "alpha")
            signed = run("sign", "--wrapped", str(wrapper_path), "--message", "hello")
            self.assertEqual(signed["algorithm"], "HMAC-SHA-256")
            checked = run(
                "verify",
                "--wrapped", str(wrapper_path),
                "--message", "hello",
                "--signature", str(signed["signature"]),
            )
            self.assertTrue(checked["valid"])
            failed = run(
                "verify",
                "--wrapped", str(wrapper_path),
                "--message", "tampered",
                "--signature", str(signed["signature"]),
            )
            self.assertFalse(failed["valid"])


if __name__ == "__main__":
    unittest.main()
