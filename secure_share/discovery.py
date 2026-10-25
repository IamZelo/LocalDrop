from __future__ import annotations

import socket
import ipaddress
import threading
from dataclasses import dataclass
from typing import Callable

from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

from .protocol import SERVICE_TYPE


def _ipv4_addresses() -> list[bytes]:
    addresses: set[str] = set()
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM):
            address = result[4][0]
            if not ipaddress.ip_address(address).is_loopback:
                addresses.add(address)
    except OSError:
        pass
    if not addresses:
        addresses.add("127.0.0.1")
    return [socket.inet_aton(address) for address in sorted(addresses)]


@dataclass(frozen=True)
class DiscoveredPeer:
    service_name: str
    host: str
    port: int
    device_id: str
    display_name: str


class _Listener(ServiceListener):
    def __init__(self, owner: "Discovery"):
        self.owner = owner

    def add_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        self._update(zc, service_type, name)

    def update_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        self._update(zc, service_type, name)

    def remove_service(self, zc: Zeroconf, service_type: str, name: str) -> None:
        self.owner._remove(name)

    def _update(self, zc: Zeroconf, service_type: str, name: str) -> None:
        info = zc.get_service_info(service_type, name, timeout=1500)
        if not info:
            return
        addresses = info.parsed_scoped_addresses()
        if not addresses:
            return
        props = {k.decode(): v.decode(errors="replace") for k, v in info.properties.items()}
        if props.get("id") == self.owner.device_id:
            return
        self.owner._update(
            DiscoveredPeer(name, addresses[0], info.port, props.get("id", ""), props.get("name", "Nearby device"))
        )


class Discovery:
    def __init__(
        self,
        device_id: str,
        display_name: str,
        port: int,
        on_change: Callable[[list[DiscoveredPeer]], None],
    ):
        self.device_id = device_id
        self.on_change = on_change
        self.peers: dict[str, DiscoveredPeer] = {}
        self.lock = threading.Lock()
        self.zc = Zeroconf()
        instance = f"LocalSecureShare-{device_id[:10]}.{SERVICE_TYPE}"
        self.info = ServiceInfo(
            SERVICE_TYPE,
            instance,
            port=port,
            properties={"id": device_id, "name": display_name, "v": "1"},
            server=f"{socket.gethostname().replace('.', '-')}.local.",
            addresses=_ipv4_addresses(),
        )
        self.zc.register_service(self.info)
        self.browser = ServiceBrowser(self.zc, SERVICE_TYPE, _Listener(self))

    def _update(self, peer: DiscoveredPeer) -> None:
        with self.lock:
            self.peers[peer.service_name] = peer
            snapshot = list(self.peers.values())
        self.on_change(snapshot)

    def _remove(self, name: str) -> None:
        with self.lock:
            self.peers.pop(name, None)
            snapshot = list(self.peers.values())
        self.on_change(snapshot)

    def close(self) -> None:
        self.zc.unregister_service(self.info)
        self.zc.close()
