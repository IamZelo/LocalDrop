import io
import socket
import tempfile
import unittest
from pathlib import Path

from secure_share.protocol import CODE_ALPHABET, hash_file, pairing_code, recv_frame, safe_filename, send_chunk, send_control, unique_destination, validate_manifest


class ProtocolTests(unittest.TestCase):
    def test_pairing_code_is_unambiguous(self):
        code = pairing_code()
        self.assertEqual(len(code), 8)
        self.assertTrue(set(code) <= set(CODE_ALPHABET))

    def test_safe_filename_blocks_traversal_and_reserved_names(self):
        self.assertEqual(safe_filename("../../hello.txt"), "hello.txt")
        self.assertEqual(safe_filename("CON"), "received_file")
        self.assertNotIn(":", safe_filename("bad:name.txt"))

    def test_framing_round_trip(self):
        left, right = socket.socketpair()
        try:
            send_control(left, {"type": "hello", "n": 1})
            self.assertEqual(recv_frame(right), ("json", {"n": 1, "type": "hello"}))
            send_chunk(left, b"abc")
            self.assertEqual(recv_frame(right), ("chunk", b"abc"))
        finally:
            left.close()
            right.close()

    def test_hash_and_unique_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            source.write_bytes(b"abc")
            self.assertEqual(hash_file(source), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            self.assertEqual(unique_destination(root, "file.txt").name, "file.txt")
            (root / "file.txt").write_text("x")
            self.assertEqual(unique_destination(root, "file.txt").name, "file (1).txt")

    def test_manifest_validation(self):
        good = [{"name": "a.txt", "size": 3, "sha256": "a" * 64}]
        self.assertEqual(validate_manifest(good), good)
        for bad in ([], [{"name": "a", "size": -1, "sha256": "a" * 64}], [{"name": "a", "size": 1, "sha256": "no"}]):
            with self.assertRaises(ValueError):
                validate_manifest(bad)


if __name__ == "__main__":
    unittest.main()
