from dataclasses import dataclass
import sys

@dataclass(frozen=True)
class PeerLinkCapability:
    mode: str
    available: bool
    detail: str

def peer_link_capability() -> PeerLinkCapability:
    if sys.platform != "win32":
        return PeerLinkCapability("Wi-Fi Direct", False, "Only Windows 11 is currently implemented.")
    from .winrt_radio import available
    ready = available()
    return PeerLinkCapability("Windows Wi-Fi Direct", ready,
        "Python WinRT installed; adapter support is checked at runtime." if ready
        else "Install the Windows packages from requirements.txt.")
