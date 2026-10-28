import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secure_share.identity import Identity, update_display_name


class IdentityProfileTests(unittest.TestCase):
    def test_display_name_update_preserves_cryptographic_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = Identity(
                "device-id", "Old Name", Ed25519PrivateKey.generate(), root / "identity.crt"
            )
            with patch("secure_share.identity.app_data_dir", return_value=root):
                updated = update_display_name(identity, "  My Laptop  ")
            self.assertEqual(updated.display_name, "My Laptop")
            self.assertEqual(updated.device_id, identity.device_id)
            self.assertIs(updated.private_key, identity.private_key)
            profile = json.loads((root / "profile.json").read_text(encoding="utf-8"))
            self.assertEqual(profile, {"device_id": "device-id", "display_name": "My Laptop"})

    def test_display_name_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = Identity(
                "device-id", "Old Name", Ed25519PrivateKey.generate(), root / "identity.crt"
            )
            with patch("secure_share.identity.app_data_dir", return_value=root):
                for invalid in ("   ", "bad\nname", "é" * 41):
                    with self.assertRaises(ValueError):
                        update_display_name(identity, invalid)


if __name__ == "__main__":
    unittest.main()
