import unittest

from secure_share.winrt_radio import _decode_hostname, _encode_hostname


class WinRTRadioTests(unittest.TestCase):
    def test_common_windows_hostname_fits_ble_payload(self):
        encoded = _encode_hostname("DESKTOP-CS6DRQK")
        self.assertLessEqual(len(encoded), 10)
        self.assertEqual(_decode_hostname(encoded), "DESKTOP-CS6DRQK")

    def test_general_hostname_is_safely_truncated(self):
        encoded = _encode_hostname("engineering-workstation")
        self.assertLessEqual(len(encoded), 10)
        self.assertEqual(_decode_hostname(encoded), "engineeri")


if __name__ == "__main__":
    unittest.main()
