import sys
import unittest

from secure_share.winrt_radio import (
    PythonWinRTRadio,
    RadioOperationError,
    _decode_hostname,
    _encode_hostname,
    _exception_event,
)


@unittest.skipUnless(sys.platform == "win32", "WinRT tests require Windows")
class WinRTRadioTests(unittest.TestCase):
    def test_common_windows_hostname_fits_ble_payload(self):
        encoded = _encode_hostname("DESKTOP-CS6DRQK")
        self.assertLessEqual(len(encoded), 10)
        self.assertEqual(_decode_hostname(encoded), "DESKTOP-CS6DRQK")

    def test_general_hostname_is_safely_truncated(self):
        encoded = _encode_hostname("engineering-workstation")
        self.assertLessEqual(len(encoded), 10)
        self.assertEqual(_decode_hostname(encoded), "engineeri")

    def test_structured_error_contains_phase_hresult_and_traceback(self):
        try:
            error = RadioOperationError("windows_pairing", "denied", status="ACCESS_DENIED")
            error.hresult = -2147024891
            raise error
        except RadioOperationError as exc:
            event = _exception_event("bluetooth_metadata_error", exc, "ABC12345")
        self.assertEqual(event["phase"], "windows_pairing")
        self.assertEqual(event["status"], "ACCESS_DENIED")
        self.assertEqual(event["hresult"], "0x80070005 (-2147024891)")
        self.assertIn("RadioOperationError", event["traceback"])

    def test_wifi_direct_is_locked_before_bluetooth_metadata(self):
        radio = PythonWinRTRadio("device", 43123, lambda _event: None)
        with self.assertRaisesRegex(RuntimeError, "Bluetooth bootstrap metadata"):
            radio.scan_wifi_direct()


if __name__ == "__main__":
    unittest.main()
