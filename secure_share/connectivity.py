from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Iterable


class Transport(str, enum.Enum):
    LAN = "lan"
    WIFI_DIRECT = "wifi_direct"


class TransferPhase(str, enum.Enum):
    CONNECT = "connect"
    TLS_HANDSHAKE = "tls_handshake"
    OFFER = "offer"
    APPROVAL = "receiver_approval"
    STREAM = "file_stream"
    VERIFY = "receiver_verification"
    COMPLETE = "complete"


@dataclass(frozen=True)
class ConnectionRoute:
    transport: Transport
    device_id: str
    display_name: str
    public_key: str
    host: str = ""
    port: int = 0
    local_interface: str | None = None
    fresh_at: float = field(default_factory=time.monotonic)
    attempt_id: str = ""
    endpoint_id: str | None = None


@dataclass(frozen=True)
class ConnectionAttempt:
    device_id: str
    routes: tuple[ConnectionRoute, ...]
    attempt_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_at: float = field(default_factory=time.monotonic)


@dataclass(frozen=True)
class TransferResult:
    succeeded: bool
    phase: TransferPhase
    retryable: bool = False
    offer_sent: bool = False
    message: str = ""
    attempt_id: str = ""
    transport: Transport | None = None
    cancelled: bool = False

    @property
    def may_fallback(self) -> bool:
        return not self.succeeded and self.retryable and not self.offer_sent


@dataclass(frozen=True)
class RouteOutcome:
    device_id: str
    transport: Transport
    endpoint: str
    phase: TransferPhase
    duration: float
    succeeded: bool
    retryable: bool = False
    offer_sent: bool = False


ROUTE_ORDER = {Transport.LAN: 0, Transport.WIFI_DIRECT: 1}


def ordered_routes(routes: Iterable[ConnectionRoute]) -> tuple[ConnectionRoute, ...]:
    return tuple(sorted(routes, key=lambda route: (ROUTE_ORDER[route.transport], -route.fresh_at)))


class ConnectivityCoordinator:
    """Small policy engine; platform setup and transfer I/O stay injectable."""

    def __init__(self, attempt_route: Callable[[ConnectionRoute], TransferResult]):
        self.attempt_route = attempt_route

    def run(self, attempt: ConnectionAttempt) -> TransferResult:
        last = TransferResult(False, TransferPhase.CONNECT, message="No available route")
        for route in ordered_routes(attempt.routes):
            result = self.attempt_route(route)
            last = result
            if result.succeeded or not result.may_fallback:
                return result
        return last
