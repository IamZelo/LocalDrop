import unittest

from secure_share.connectivity import (
    ConnectionAttempt, ConnectionRoute, ConnectivityCoordinator, TransferPhase,
    TransferResult, Transport, ordered_routes,
)


class ConnectivityTests(unittest.TestCase):
    def routes(self):
        return [ConnectionRoute(Transport.WIFI_DIRECT, "peer", "Peer", "key"),
                ConnectionRoute(Transport.HOTSPOT, "peer", "Peer", "key"),
                ConnectionRoute(Transport.LAN, "peer", "Peer", "key", "192.168.1.2", 1234)]

    def test_route_precedence(self):
        self.assertEqual([route.transport for route in ordered_routes(self.routes())],
                         [Transport.LAN, Transport.HOTSPOT, Transport.WIFI_DIRECT])

    def test_fallback_only_before_offer(self):
        seen = []
        def run(route):
            seen.append(route.transport)
            return TransferResult(False, TransferPhase.CONNECT, True, route.transport != Transport.LAN)
        ConnectivityCoordinator(run).run(ConnectionAttempt("peer", tuple(self.routes())))
        self.assertEqual(seen, [Transport.LAN, Transport.HOTSPOT])

    def test_identity_failure_is_terminal(self):
        seen = []
        def run(route):
            seen.append(route.transport)
            return TransferResult(False, TransferPhase.TLS_HANDSHAKE, False, False)
        ConnectivityCoordinator(run).run(ConnectionAttempt("peer", tuple(self.routes())))
        self.assertEqual(seen, [Transport.LAN])

