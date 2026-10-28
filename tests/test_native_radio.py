from __future__ import annotations

import threading
import time
import unittest

from secure_share.native_radio import ThreadedWinRTRadio


class FakeBackend:
    instances: list["FakeBackend"] = []

    def __init__(self, *_args, **_kwargs):
        self.start_error = None
        self.started_on = None
        self.scanned_on = None
        self.scan_called = threading.Event()
        self.close_started = threading.Event()
        self.allow_close = threading.Event()
        self.closed = False
        self.__class__.instances.append(self)

    def start(self) -> bool:
        self.started_on = threading.get_ident()
        return True

    def scan_wifi_direct(self) -> None:
        self.scanned_on = threading.get_ident()
        self.scan_called.set()

    def close(self) -> None:
        if self.closed:
            return
        self.close_started.set()
        self.allow_close.wait(2)
        self.closed = True


class ThreadedWinRTRadioTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeBackend.instances.clear()

    def test_commands_and_blocking_close_stay_off_caller_thread(self) -> None:
        caller_thread = threading.get_ident()
        radio = ThreadedWinRTRadio(FakeBackend, "device", 43123, lambda _event: None)
        self.assertTrue(radio.start())

        deadline = time.monotonic() + 2
        while radio.backend is None and time.monotonic() < deadline:
            time.sleep(0.01)
        backend = radio.backend
        self.assertIsNotNone(backend)

        radio.scan_wifi_direct()
        self.assertTrue(backend.scan_called.wait(2))
        self.assertNotEqual(backend.started_on, caller_thread)
        self.assertEqual(backend.scanned_on, backend.started_on)

        started = time.monotonic()
        radio.close()
        self.assertLess(time.monotonic() - started, 0.1)
        self.assertTrue(backend.close_started.wait(2))
        backend.allow_close.set()
        radio.thread.join(2)
        self.assertFalse(radio.thread.is_alive())


if __name__ == "__main__":
    unittest.main()
