import asyncio
import base64
import unittest
from unittest.mock import Mock, AsyncMock
from radio_test_support import load

radio_module = load("winrt_radio")

class WinRTRadioTests(unittest.IsolatedAsyncioTestCase):
    def test_advertisement_name_round_trip_and_legacy_compatibility(self):
        key = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")
        payload = radio_module._advertisement_payload(
            "device-id", 43123, b"12345678", key, "Harsh's Laptop"
        )
        parsed = radio_module._parse_advertisement_payload(payload)
        self.assertEqual(parsed[1:3], (43123, "device-id"))
        self.assertEqual(parsed[4], "Harsh's Laptop")
        legacy = payload[:-(1 + len("Harsh's Laptop"))]
        self.assertEqual(radio_module._parse_advertisement_payload(legacy)[4], "")

    def test_advertisement_rejects_oversized_profile_name(self):
        key = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")
        with self.assertRaisesRegex(ValueError, "name is too long"):
            radio_module._advertisement_payload("device", 43123, b"12345678", key, "x" * 81)

    def test_no_bluetooth_packages_required(self):
        self.assertFalse(any("bluetooth" in name for name in radio_module.REQUIRED_MODULES))

    def test_startup_required_for_scanning(self):
        radio = radio_module.PythonWinRTRadio("device", 43123, Mock())
        with self.assertRaisesRegex(RuntimeError, "not ready"):
            radio.scan_wifi_direct()

    def test_skipped_scan_always_completes(self):
        callback = Mock()
        radio = radio_module.PythonWinRTRadio("device", 43123, callback)
        radio.started = True
        radio._scanning = True
        radio.scan_wifi_direct()
        self.assertEqual(callback.call_args.args[0]["event"], "wifi_direct_scan_complete")

    async def test_startup_uses_only_wifi(self):
        events = []
        radio = radio_module.PythonWinRTRadio("device", 43123, events.append)
        radio._start_wifi_direct = Mock(side_effect=lambda: radio.publisher_ready.set())
        task = asyncio.create_task(radio._main())
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertTrue(radio.started)
        radio._start_wifi_direct.assert_called_once()
        self.assertEqual(events[0]["event"], "ready")
        radio.stop_event.set()
        await task

    async def test_connection_timeout_has_attempt_id(self):
        events = []
        radio = radio_module.PythonWinRTRadio("device", 43123, events.append)
        radio._connect_wifi_direct = AsyncMock(side_effect=TimeoutError)
        await radio._connect_attempt("endpoint", "attempt")
        self.assertEqual(events[0]["attempt_id"], "attempt")
        self.assertEqual(events[0]["phase"], "wifi_direct_connect")

    def test_structured_error_contains_hresult(self):
        error = radio_module.RadioOperationError("connect", "denied", status="ACCESS_DENIED")
        error.hresult = -2147024891
        event = radio_module._exception_event("wifi_direct_error", error, "attempt")
        self.assertEqual(event["hresult"], "0x80070005 (-2147024891)")
        self.assertEqual(event["attempt_id"], "attempt")
