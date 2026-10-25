from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass

from .native_radio import helper_path


@dataclass(frozen=True)
class PeerLinkCapability:
    mode: str
    available: bool
    detail: str


def peer_link_capability() -> PeerLinkCapability:
    """Report native-link capability without silently changing network state."""
    if os.name == "nt":
        try:
            from .winrt_radio import available as python_winrt_available
        except ImportError:
            python_winrt_available = lambda: False
        if python_winrt_available():
            return PeerLinkCapability(
                "Windows BLE + Wi-Fi Direct",
                True,
                "Native Bluetooth discovery and Wi-Fi Direct are active through Python WinRT.",
            )
        if helper_path().exists():
            return PeerLinkCapability(
                "Windows BLE + Wi-Fi Direct",
                True,
                "Native Bluetooth discovery and Wi-Fi Direct are active.",
            )
        return PeerLinkCapability(
            "Windows Wi-Fi Direct",
            False,
            "Install the Windows WinRT packages from requirements.txt; LAN discovery remains active.",
        )
    if sys.platform == "darwin":
        return PeerLinkCapability(
            "Apple peer-to-peer Wi-Fi",
            False,
            "The signed Network.framework helper is not bundled in this source build; use a LAN or Personal Hotspot.",
        )
    if shutil.which("wpa_cli"):
        return PeerLinkCapability(
            "Linux Wi-Fi Direct",
            False,
            "Compatible hardware detected; automatic group creation needs a distribution-specific privileged helper. Use a hotspot for now.",
        )
    return PeerLinkCapability("Local network", False, "Connect both devices to the same LAN or hotspot.")
