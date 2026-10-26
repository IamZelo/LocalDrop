from __future__ import annotations

import asyncio
import logging
import platform
import sys

from PySide6.QtCore import QCoreApplication
from qasync import QEventLoop

from .discovery import _ipv4_addresses


def main() -> int:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    print(f"Python: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Executable: {sys.executable}")
    print(f"mDNS IPv4 address count: {len(_ipv4_addresses())}")
    if sys.platform != "win32":
        print("Wi-Fi Direct: not applicable on this platform")
        return 0

    from .native_radio import NativeRadio
    from .winrt_radio import missing_modules
    print(f"Missing WinRT modules: {missing_modules() or 'none'}")
    print("Radio backend policy: Python WinRT only (no helper fallback)")

    startup = {"ready": False, "failed": False}

    def event(value: dict) -> None:
        if value.get("event") == "ready":
            startup["ready"] = True
        elif value.get("event") == "fatal":
            startup["failed"] = True
        traceback_text = value.get("traceback")
        summary = {key: item for key, item in value.items() if key != "traceback"}
        print(f"RADIO EVENT: {summary}", flush=True)
        if traceback_text:
            print(f"FULL TRACEBACK:\n{traceback_text}", file=sys.stderr, flush=True)

    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    radio = NativeRadio("diagnostic-device", 43123, event)
    print(f"Selected backend: {radio.implementation}")

    async def observe() -> int:
        if not radio.start():
            print("RESULT: radio failed to start", file=sys.stderr)
            return 1
        try:
            print("Waiting for Wi-Fi Direct startup, then scanning for up to 30 seconds...")
            print("Wi-Fi Direct startup is pending; watch publisher status below.")
            for _ in range(250):
                if startup["ready"] or startup["failed"]:
                    break
                await asyncio.sleep(0.1)
            if not startup["ready"]:
                print("RESULT: Wi-Fi Direct startup failed", file=sys.stderr)
                return 1
            radio.scan_wifi_direct()
            await asyncio.sleep(30)
            print("RESULT: radio backend remained running")
            return 0
        finally:
            radio.close()
            await asyncio.sleep(0)

    with loop:
        return loop.run_until_complete(observe())


if __name__ == "__main__":
    raise SystemExit(main())
