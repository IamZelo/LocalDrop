from __future__ import annotations

import logging
import platform
import sys
import time

from .native_radio import NativeRadio, helper_path
from .winrt_radio import missing_modules


def main() -> int:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    print(f"Python: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Executable: {sys.executable}")
    print(f"Missing WinRT modules: {missing_modules() or 'none'}")
    print(f"Legacy helper: {helper_path()} (exists={helper_path().exists()})")

    def event(value: dict) -> None:
        print(f"RADIO EVENT: {value}", flush=True)

    radio = NativeRadio("diagnostic-device", 43123, event)
    print(f"Selected backend: {radio.implementation}")
    if not radio.start():
        print("RESULT: radio failed to start", file=sys.stderr)
        return 1
    try:
        print("Radio started; observing Bluetooth for 3 seconds…")
        time.sleep(3)
        print("Requesting a Wi-Fi Direct scan…")
        radio.scan_wifi_direct()
        time.sleep(5)
        print("RESULT: radio backend remained running")
        return 0
    finally:
        radio.close()


if __name__ == "__main__":
    raise SystemExit(main())
