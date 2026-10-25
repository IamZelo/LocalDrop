from __future__ import annotations

import logging
import sys
from typing import Callable

logger = logging.getLogger("secure_share.radio")


class UnavailableRadio:
    def __init__(self, reason: str):
        self.reason = reason

    @property
    def supported(self) -> bool:
        return False

    def start(self) -> bool:
        logger.error("Radio backend unavailable: %s", self.reason)
        return False

    def scan_wifi_direct(self) -> None:
        raise RuntimeError(self.reason)

    def connect_wifi_direct(self, _device_id: str, _attempt_id: str) -> None:
        raise RuntimeError(self.reason)



    def close(self) -> None:
        return


class NativeRadio:
    """Single Windows radio implementation backed by in-process PyWinRT."""

    def __init__(
        self, device_id: str, port: int, on_event: Callable[[dict], None], public_key: str = ""
    ):
        self.on_event = on_event
        self.implementation = "unavailable"
        if sys.platform != "win32":
            self.backend = UnavailableRadio("This Wi-Fi Direct implementation requires Windows 11")
            return
        try:
            from .winrt_radio import PythonWinRTRadio, missing_modules

            missing = missing_modules()
            if missing:
                reason = (
                    f"Python WinRT packages are incomplete: {', '.join(missing)}. "
                    "Run: python -m pip install -r requirements.txt"
                )
                logger.error(reason)
                self.backend = UnavailableRadio(reason)
                return
            self.backend = PythonWinRTRadio(device_id, port, on_event, public_key=public_key)
            self.implementation = "python-winrt"
            logger.info("Selected radio backend: Python WinRT (single backend; no helper fallback)")
        except Exception as exc:
            logger.exception("Could not inspect or load Python WinRT")
            reason = f"Could not load Python WinRT: {exc}"
            on_event({"event": "error", "message": reason})
            self.backend = UnavailableRadio(reason)

    @property
    def supported(self) -> bool:
        return self.backend.supported

    def start(self) -> bool:
        started = self.backend.start()
        if not started and self.implementation == "python-winrt":
            logger.error("Python WinRT startup failed; no alternate backend is configured")
        return started

    def scan_wifi_direct(self) -> None:
        self.backend.scan_wifi_direct()

    def connect_wifi_direct(self, device_id: str, attempt_id: str) -> None:
        self.backend.connect_wifi_direct(device_id, attempt_id)

    def reset_wifi_direct(self) -> None:
        if self.supported:
            self.backend.reset_wifi_direct()



    def close(self) -> None:
        self.backend.close()
