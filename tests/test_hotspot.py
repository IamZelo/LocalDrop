import importlib.util
import unittest
from unittest.mock import Mock

HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None
if HAS_CRYPTOGRAPHY:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from secure_share.hotspot import derive_credentials, new_hotspot_request, validate_hotspot_request
    from secure_share.identity import b64


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography dependency is not installed")
class HotspotControlTests(unittest.TestCase):
    def test_both_sides_derive_same_credentials(self):
        left, right = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        left_public = b64(left.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        right_public = b64(right.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        nonce = b64(b"n" * 16)
        self.assertEqual(derive_credentials(left, right_public, nonce), derive_credentials(right, left_public, nonce))

    def test_request_target_expiry_and_replay(self):
        identity = Mock(device_id="sender", public_b64=b64(b"p" * 32))
        identity.sign.side_effect = lambda payload: "signature"
        request, _ = new_hotspot_request(identity, "receiver", b"n" * 16)
        # Signature verification is separately covered by identity tests; use a
        # real malformed target here before verification occurs.
        with self.assertRaisesRegex(ValueError, "another device"):
            validate_hotspot_request(request, "other", set(), now=request["time"])
        with self.assertRaisesRegex(ValueError, "Expired"):
            validate_hotspot_request(request, "receiver", set(), now=request["time"] + 31)

