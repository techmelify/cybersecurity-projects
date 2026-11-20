import base64
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chat import (  # noqa: E402
    LAB_PHRASE,
    AuthError,
    ChatMessage,
    ChatStore,
    DuplicateSequenceError,
    StoreFormatError,
    derive_lab_key,
    decrypt_payload,
    encrypt_payload,
    load_key_file,
    main,
    write_key_file,
)


def message(sequence=1, sender="alice", body="hello", timestamp="2026-01-01T00:00:00Z"):
    return ChatMessage(sequence, sender, body, timestamp)


class ChatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "chat.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_lab_key_is_public_derivation(self):
        import hashlib

        self.assertEqual(derive_lab_key(), hashlib.sha256(LAB_PHRASE.encode()).digest())
        self.assertEqual(len(derive_lab_key()), 32)

    def test_round_trip(self):
        store = ChatStore(self.path)
        store.append(message())
        store.append(message(2, "bob", "ack", "2026-01-01T00:00:05Z"))
        loaded = ChatStore(self.path).read()
        self.assertEqual([m.sender for m in loaded], ["alice", "bob"])
        self.assertEqual(loaded[1].body, "ack")

    def test_store_contains_no_plaintext(self):
        ChatStore(self.path).append(message(body="top secret text"))
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("top secret text", raw)
        self.assertNotIn("alice", raw)
        self.assertIn("ciphertext", raw)

    def test_each_message_gets_a_distinct_nonce(self):
        store = ChatStore(self.path)
        for sequence in range(1, 6):
            store.append(message(sequence=sequence))
        document = json.loads(self.path.read_text(encoding="utf-8"))
        nonces = {base64.b64decode(r["nonce"]) for r in document["messages"]}
        self.assertEqual(len(nonces), 5)

    def test_fixed_nonce_is_deterministic(self):
        nonce = bytes(range(12))
        first = ChatStore(Path(self.tmp.name) / "a.json").append(message(), nonce=nonce)
        second = ChatStore(Path(self.tmp.name) / "b.json").append(message(), nonce=nonce)
        self.assertEqual(first, second)

    def test_tampering_is_detected(self):
        store = ChatStore(self.path)
        store.append(message())
        document = json.loads(self.path.read_text(encoding="utf-8"))
        raw = bytearray(base64.b64decode(document["messages"][0]["ciphertext"]))
        raw[-1] ^= 1
        document["messages"][0]["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
        self.path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(AuthError):
            ChatStore(self.path).read()

    def test_wrong_key_cannot_read(self):
        ChatStore(self.path).append(message())
        other_key = derive_lab_key("a different phrase")
        with self.assertRaises(AuthError):
            ChatStore(self.path, other_key).read()

    def test_key_never_appears_in_repr_or_errors(self):
        key = derive_lab_key()
        store = ChatStore(self.path)
        store.append(message())
        self.assertNotIn(key.hex(), repr(store))
        self.assertNotIn(key.hex(), self.path.read_text(encoding="utf-8"))
        with self.assertRaises(AuthError) as caught:
            ChatStore(self.path, derive_lab_key("other")).read()
        self.assertNotIn(key.hex(), str(caught.exception))

    def test_duplicate_sequence_rejected(self):
        store = ChatStore(self.path)
        store.append(message())
        with self.assertRaises(DuplicateSequenceError):
            store.append(message(body="different"))

    def test_bad_store_format(self):
        self.path.write_text(json.dumps({"format": "nope"}), encoding="utf-8")
        with self.assertRaises(StoreFormatError):
            ChatStore(self.path)

    def test_key_file_round_trip(self):
        key_path = Path(self.tmp.name) / "lab.key"
        write_key_file(key_path)
        key = load_key_file(key_path)
        self.assertEqual(len(key), 32)
        self.assertNotIn(key.hex(), repr(ChatStore(self.path, key)))

    def test_encrypt_rejects_short_nonce(self):
        with self.assertRaises(ValueError):
            encrypt_payload(derive_lab_key(), b"short", message())

    def test_decrypt_rejects_sequence_mismatch(self):
        nonce = bytes(range(12))
        ciphertext = encrypt_payload(derive_lab_key(), nonce, message(sequence=1))
        with self.assertRaises(AuthError):
            decrypt_payload(derive_lab_key(), nonce, ciphertext, 2)

    def test_cli_send_and_read(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["init", str(self.path)]), 0)
            self.assertEqual(
                main(["send", str(self.path), "alice", "from cli", "--sequence", "7", "--timestamp", "2026-01-01"]),
                0,
            )
            self.assertEqual(main(["read", str(self.path)]), 0)
        self.assertIn("[7] 2026-01-01 alice: from cli", output.getvalue())
        self.assertNotIn(derive_lab_key().hex(), output.getvalue())


if __name__ == "__main__":
    unittest.main()
