from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from typing import Callable

from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

from .connectivity import Transport
from .identity import unb64
from .protocol import SERVICE_TYPE

DISCOVERY_VERSION = 1
STALE_AFTER = 45.0


def _usable_ipv4(address: str, *, remote: bool = False) -> bool:
    try:
        value = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return (value.version == 4 and not value.is_unspecified and not value.is_multicast
            and (not remote or not value.is_loopback)
            and (value.is_private or value.is_link_local or (value.is_loopback and not remote)))


def _ipv4_addresses() -> list[bytes]:
    addresses: set[str] = set()
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM):
            address = result[4][0]
            if _usable_ipv4(address):
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
    public_key: str = ""
    protocol_version: int = DISCOVERY_VERSION
    transport: Transport = Transport.LAN
    local_interface: str | None = None
    fresh_at: float = 0.0


def peers_from_service(info: ServiceInfo, own_device_id: str, now: float | None = None) -> list[DiscoveredPeer]:
    try:
        props = {bytes(k).decode("utf-8"): bytes(v).decode("utf-8") for k, v in info.properties.items()}
        device_id, display_name, public_key = props["id"].strip(), props["name"].strip(), props["key"].strip()
        version = int(props["v"])
        if not device_id or device_id == own_device_id or not display_name or version < 1:
            return []
        if not 0 < int(info.port) < 65536 or len(unb64(public_key)) != 32:
            return []
    except (KeyError, TypeError, ValueError, UnicodeError):
        return []
    result, seen = [], set()
    for address in info.parsed_scoped_addresses():
        address = address.split("%", 1)[0]
        if address in seen or not _usable_ipv4(address, remote=True):
            continue
        seen.add(address)
        result.append(DiscoveredPeer(info.name, address, int(info.port), device_id, display_name,
                                     public_key, version, Transport.LAN, None, now or time.monotonic()))
    return result


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
        self.owner._update_service(name, peers_from_service(info, self.owner.device_id))


class Discovery:
    def __init__(
        self,
        device_id: str,
        display_name: str,
        port: int,
        public_key: str | Callable[[list[DiscoveredPeer]], None],
        on_change: Callable[[list[DiscoveredPeer]], None] | None = None,
    ):
        if on_change is None:
            on_change = public_key  # backwards-compatible four-argument form
            public_key = ""
        self.device_id = device_id
        self.display_name = display_name
        self.port = port
        self.public_key = str(public_key)
        self.on_change = on_change
        self.peers: dict[str, dict[str, DiscoveredPeer]] = {}
        self.lock = threading.Lock()
        self.zc = Zeroconf(ip_version=IPVersion.V4Only)
        instance = f"LocalSecureShare-{device_id[:10]}.{SERVICE_TYPE}"
        self.info = ServiceInfo(
            SERVICE_TYPE,
            instance,
            port=port,
            properties={"id": device_id, "name": display_name, "v": str(DISCOVERY_VERSION), "key": self.public_key},
            server=f"{socket.gethostname().replace('.', '-')}.local.",
            addresses=_ipv4_addresses(),
        )
        self.zc.register_service(self.info)
        self.browser = ServiceBrowser(self.zc, SERVICE_TYPE, _Listener(self))

    def _snapshot(self) -> list[DiscoveredPeer]:
        latest: dict[str, DiscoveredPeer] = {}
        for services in self.peers.values():
            for peer in services.values():
                if peer.device_id not in latest or peer.fresh_at > latest[peer.device_id].fresh_at:
                    latest[peer.device_id] = peer
        return list(latest.values())

    def routes_for(self, device_id: str) -> list[DiscoveredPeer]:
        with self.lock:
            return [peer for services in self.peers.values() for peer in services.values()
                    if peer.device_id == device_id]

    def _update_service(self, name: str, peers: list[DiscoveredPeer]) -> None:
        if not peers:
            return
        with self.lock:
            self.peers[name] = {peer.host: peer for peer in peers}
            snapshot = self._snapshot()
        self.on_change(snapshot)

    def _remove(self, name: str) -> None:
        with self.lock:
            self.peers.pop(name, None)
            snapshot = self._snapshot()
        self.on_change(snapshot)

    def refresh_registration(self) -> None:
        addresses = _ipv4_addresses()
        if addresses != self.info.addresses:
            self.info.addresses = addresses
            self.zc.update_service(self.info)

    def prune(self, now: float | None = None) -> None:
        cutoff = (now or time.monotonic()) - STALE_AFTER
        with self.lock:
            for name, routes in list(self.peers.items()):
                current = {host: peer for host, peer in routes.items() if peer.fresh_at >= cutoff}
                if current:
                    self.peers[name] = current
                else:
                    del self.peers[name]
            snapshot = self._snapshot()
        self.on_change(snapshot)

    def close(self) -> None:
        self.zc.unregister_service(self.info)
        self.zc.close()
