from __future__ import annotations

import asyncio
import logging
import sys
import threading
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

    def update_display_name(self, _display_name: str) -> None:
        return


    def close(self) -> None:
        return


class ThreadedWinRTRadio:
    """Own a PythonWinRTRadio and its asyncio loop on one worker thread."""

    def __init__(
        self, backend_type, device_id: str, port: int, on_event: Callable[[dict], None],
        public_key: str = "", display_name: str = "",
    ):
        self.backend_type = backend_type
        self.device_id = device_id
        self.port = port
        self.on_event = on_event
        self.public_key = public_key
        self.display_name = display_name
        self.backend = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self._closing = False

    @property
    def supported(self) -> bool:
        return True

    def start(self) -> bool:
        if self.thread is not None:
            return True
        self.thread = threading.Thread(
            target=self._run, name="wifi-direct-winrt", daemon=False
        )
        self.thread.start()
        return True

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop
        try:
            backend = self.backend_type(
                self.device_id, self.port, self.on_event,
                public_key=self.public_key, display_name=self.display_name,
            )
            self.backend = backend
            if self._closing:
                backend.close()
                return
            if not backend.start():
                self.on_event({
                    "event": "error",
                    "message": backend.start_error or "Python WinRT radio failed to start",
                })
                return
            logger.info("WinRT radio worker started on %s", threading.current_thread().name)
            loop.run_forever()
        except Exception as exc:
            logger.exception("WinRT radio worker failed")
            self.on_event({"event": "error", "message": f"Python WinRT radio failed: {exc}"})
        finally:
            if self.backend is not None:
                self.backend.close()
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()
            self.loop = None
            logger.info("WinRT radio worker stopped")

    def _dispatch(self, method: str, *args) -> None:
        loop = self.loop
        if self._closing:
            return
        if loop is None or self.backend is None:
            raise RuntimeError("Wi-Fi Direct worker is not ready yet")

        def invoke() -> None:
            try:
                getattr(self.backend, method)(*args)
            except Exception as exc:
                logger.exception("WinRT radio command failed: %s", method)
                self.on_event({"event": "wifi_direct_error", "message": str(exc)})

        loop.call_soon_threadsafe(invoke)

    def scan_wifi_direct(self) -> None:
        self._dispatch("scan_wifi_direct")

    def connect_wifi_direct(self, device_id: str, attempt_id: str) -> None:
        self._dispatch("connect_wifi_direct", device_id, attempt_id)

    def reset_wifi_direct(self) -> None:
        self._dispatch("reset_wifi_direct")

    def update_display_name(self, display_name: str) -> None:
        self.display_name = display_name
        self._dispatch("update_display_name", display_name)

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        loop = self.loop
        backend = self.backend
        if loop is None or backend is None:
            return

        def stop() -> None:
            backend.close()
            loop.stop()

        loop.call_soon_threadsafe(stop)


class NativeRadio:
    """Single Windows radio implementation backed by in-process PyWinRT."""

    def __init__(
        self, device_id: str, port: int, on_event: Callable[[dict], None], public_key: str = "",
        display_name: str = "",
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
            self.backend = ThreadedWinRTRadio(
                PythonWinRTRadio,
                device_id, port, on_event, public_key=public_key, display_name=display_name
            )
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

    def update_display_name(self, display_name: str) -> None:
        self.backend.update_display_name(display_name)


    def close(self) -> None:
        self.backend.close()
