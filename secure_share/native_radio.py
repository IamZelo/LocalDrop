from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable

logger = logging.getLogger("secure_share.radio")


def helper_path() -> Path:
    override = os.environ.get("LOCAL_SECURE_SHARE_RADIO_HELPER")
    if override:
        return Path(override)
    root = Path(__file__).resolve().parent.parent
    return root / "native/windows/LocalShare.RadioHelper/bin/Release/net9.0-windows10.0.26100.0/LocalShare.RadioHelper.exe"


class HelperNativeRadio:
    """JSON-lines bridge to the native BLE and Wi-Fi Direct helper."""

    def __init__(self, device_id: str, port: int, on_event: Callable[[dict], None]):
        self.device_id = device_id
        self.port = port
        self.on_event = on_event
        self.process: subprocess.Popen[str] | None = None
        self.lock = threading.Lock()
        self.stdout_thread: threading.Thread | None = None
        self.stderr_thread: threading.Thread | None = None

    @property
    def supported(self) -> bool:
        return sys.platform == "win32" and helper_path().exists()

    def start(self) -> bool:
        if not self.supported:
            logger.error("Legacy helper not found at %s", helper_path())
            return False
        logger.info("Starting legacy radio helper: %s", helper_path())
        # A new unlinkable token is emitted for every application launch.
        token = hashlib.sha256(self.device_id.encode() + os.urandom(32)).digest()[:8].hex()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            [str(helper_path()), "--token", token, "--port", str(self.port), "--device-id", self.device_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            creationflags=flags,
        )
        self.stdout_thread = threading.Thread(target=self._read_stdout, args=(self.process,), daemon=True, name="native-radio-events")
        self.stderr_thread = threading.Thread(target=self._read_stderr, args=(self.process,), daemon=True, name="native-radio-errors")
        self.stdout_thread.start()
        self.stderr_thread.start()
        return True

    def _read_stdout(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout
        for line in process.stdout:
            try:
                self.on_event(json.loads(line))
            except (json.JSONDecodeError, TypeError) as exc:
                self.on_event({"event": "error", "message": f"Invalid native-helper response: {exc}"})
        code = process.poll()
        if code not in (None, 0):
            logger.error("Legacy native helper exited with code %s", code)
            self.on_event({"event": "fatal", "message": f"Native radio helper exited with code {code}"})

    def _read_stderr(self, process: subprocess.Popen[str]) -> None:
        assert process.stderr
        for line in process.stderr:
            if line.strip():
                logger.error("Legacy helper stderr: %s", line.strip())
                self.on_event({"event": "error", "message": line.strip()})

    def command(self, command: str, **values: object) -> None:
        with self.lock:
            if not self.process or self.process.poll() is not None or not self.process.stdin:
                raise RuntimeError("Native radio helper is not running")
            self.process.stdin.write(json.dumps({"command": command, **values}) + "\n")
            self.process.stdin.flush()

    def scan_wifi_direct(self) -> None:
        self.command("scan_wifi_direct")

    def connect_wifi_direct(self, device_id: str) -> None:
        self.command("connect_wifi_direct", id=device_id)

    def prepare_bluetooth(self, device_id: str, address: str, address_type: str) -> None:
        raise RuntimeError("Bluetooth metadata exchange requires the Python WinRT backend")

    def cancel_bluetooth_preparation(self) -> None:
        return

    def close(self) -> None:
        process = self.process
        if not process:
            return
        try:
            self.command("stop")
            process.wait(timeout=3)
        except Exception:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        for thread in (self.stdout_thread, self.stderr_thread):
            if thread and thread is not threading.current_thread():
                thread.join(timeout=2)
        if self.process is process:
            self.process = None
        self.stdout_thread = None
        self.stderr_thread = None


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

    def connect_wifi_direct(self, _device_id: str) -> None:
        raise RuntimeError(self.reason)

    def prepare_bluetooth(self, _device_id: str, _address: str, _address_type: str) -> None:
        raise RuntimeError(self.reason)

    def cancel_bluetooth_preparation(self) -> None:
        return

    def close(self) -> None:
        return


class NativeRadio:
    """Single Windows radio implementation backed by in-process PyWinRT."""

    def __init__(self, device_id: str, port: int, on_event: Callable[[dict], None]):
        self.on_event = on_event
        self.implementation = "unavailable"
        if sys.platform != "win32":
            self.backend = UnavailableRadio("Native Bluetooth and Wi-Fi Direct require Windows 11")
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
            self.backend = PythonWinRTRadio(device_id, port, on_event)
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
            logger.error("Python WinRT startup failed; legacy helper fallback is disabled for the BLE pairing workflow")
        return started

    def scan_wifi_direct(self) -> None:
        self.backend.scan_wifi_direct()

    def connect_wifi_direct(self, device_id: str) -> None:
        self.backend.connect_wifi_direct(device_id)

    def prepare_bluetooth(self, device_id: str, address: str, address_type: str) -> None:
        self.backend.prepare_bluetooth(device_id, address, address_type)

    def cancel_bluetooth_preparation(self) -> None:
        self.backend.cancel_bluetooth_preparation()

    def close(self) -> None:
        self.backend.close()
