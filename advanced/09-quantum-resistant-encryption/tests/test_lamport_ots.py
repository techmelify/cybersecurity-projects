import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lamport_ots import (  # noqa: E402
    DIGEST_BITS,
    SECRET_BYTES,
    Signature,
    generate_keypair,
    leaked_secret_indexes,
    main,
    private_key_from_dict,
    private_key_to_dict,
    public_key_from_dict,
    public_key_from_private,
    public_key_to_dict,
    sign,
    signature_from_dict,
    signature_to_dict,
    verify,
)


class LamportOtsTests(unittest.TestCase):
    def setUp(self):
        self.pair = generate_keypair(1234)
        self.message = b"measured once"

    def test_keypair_generation_is_deterministic(self):
        self.assertEqual(generate_keypair(1234), self.pair)

    def test_different_seeds_give_different_private_keys(self):
        other = generate_keypair(1235)
        self.assertNotEqual(self.pair.private.secrets[0], other.private.secrets[0])

    def test_public_key_is_hash_of_private_values(self):
        self.assertEqual(public_key_from_private(self.pair.private), self.pair.public)
        self.assertEqual(len(self.pair.public.hashes), DIGEST_BITS)

    def test_signature_has_one_part_per_bit(self):
        signature = sign(self.pair.private, self.message)
        self.assertEqual(len(signature.parts), DIGEST_BITS)
        self.assertTrue(all(len(part) == SECRET_BYTES for part in signature.parts))

    def test_valid_signature_verifies(self):
        signature = sign(self.pair.private, self.message)
        self.assertTrue(verify(self.pair.public, self.message, signature))

    def test_tampered_message_fails(self):
        signature = sign(self.pair.private, self.message)
        self.assertFalse(verify(self.pair.public, b"changed message", signature))

    def test_tampered_signature_fails(self):
        signature = sign(self.pair.private, self.message)
        changed = replace(signature, parts=(b"\x00" * SECRET_BYTES, *signature.parts[1:]))
        self.assertFalse(verify(self.pair.public, self.message, changed))

    def test_truncated_signature_fails(self):
        signature = sign(self.pair.private, self.message)
        self.assertFalse(verify(self.pair.public, self.message, Signature(signature.parts[:-1])))

    def test_wrong_public_key_fails(self):
        signature = sign(self.pair.private, self.message)
        other = generate_keypair(999)
        self.assertFalse(verify(other.public, self.message, signature))

    def test_reuse_reveals_secret_positions(self):
        first = sign(self.pair.private, b"message one")
        second = sign(self.pair.private, b"message two")
        leaked = leaked_secret_indexes(first, b"message one", second, b"message two")
        self.assertGreater(len(leaked), 0)
        self.assertTrue(all(0 <= index < DIGEST_BITS for index in leaked))

    def test_reuse_of_same_message_adds_no_new_secrets(self):
        first = sign(self.pair.private, self.message)
        second = sign(self.pair.private, self.message)
        self.assertEqual(leaked_secret_indexes(first, self.message, second, self.message), ())

    def test_private_key_serialization_round_trip(self):
        payload = private_key_to_dict(self.pair.private)
        restored = private_key_from_dict(json.loads(json.dumps(payload)))
        self.assertEqual(restored, self.pair.private)

    def test_public_and_signature_serialization_round_trip(self):
        signature = sign(self.pair.private, self.message)
        public = public_key_from_dict(json.loads(json.dumps(public_key_to_dict(self.pair.public))))
        restored = signature_from_dict(json.loads(json.dumps(signature_to_dict(signature))))
        self.assertTrue(verify(public, self.message, restored))

    def test_bad_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            private_key_from_dict({"scheme": "other", "secrets": []})

    def test_cli_keygen_sign_verify_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            private_path = Path(tmp) / "private.json"
            public_path = Path(tmp) / "public.json"
            signature_path = Path(tmp) / "signature.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main([
                        "keygen",
                        "--seed",
                        "42",
                        "--private-out",
                        str(private_path),
                        "--public-out",
                        str(public_path),
                    ]),
                    0,
                )
                self.assertEqual(
                    main([
                        "sign",
                        "--private",
                        str(private_path),
                        "--message",
                        "cli message",
                        "--output",
                        str(signature_path),
                    ]),
                    0,
                )
                verify_stdout = io.StringIO()
                with redirect_stdout(verify_stdout):
                    code = main([
                        "verify",
                        "--public",
                        str(public_path),
                        "--message",
                        "cli message",
                        "--signature",
                        str(signature_path),
                    ])
            self.assertEqual(code, 0)
            self.assertEqual(verify_stdout.getvalue().strip(), "valid")

    def test_cli_verify_wrong_message_returns_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            private_path = Path(tmp) / "private.json"
            public_path = Path(tmp) / "public.json"
            signature_path = Path(tmp) / "signature.json"
            pair = generate_keypair(11)
            private_path.write_text(json.dumps(private_key_to_dict(pair.private)), encoding="utf-8")
            public_path.write_text(json.dumps(public_key_to_dict(pair.public)), encoding="utf-8")
            signature_path.write_text(
                json.dumps(signature_to_dict(sign(pair.private, b"original"))),
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()):
                code = main([
                    "verify",
                    "--public",
                    str(public_path),
                    "--message",
                    "different",
                    "--signature",
                    str(signature_path),
                ])
            self.assertEqual(code, 1)

    def test_cli_reuse_demo_reports_leak(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main([
                "reuse-demo",
                "--seed",
                "5",
                "--message-a",
                "alpha",
                "--message-b",
                "beta",
            ])
        self.assertEqual(code, 0)
        self.assertIn("distinct secret positions", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
