import base64
import unittest
from unittest.mock import Mock
from radio_test_support import load

app = load("app")

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.window = object.__new__(app.MainWindow)
        w = self.window
        for name in ("network", "store", "status", "progress", "radio", "scan_timer", "radio_status", "identity"):
            setattr(w, name, Mock())
        w.store.peer.return_value = None
        w.identity.device_id = "self"
        w.workflow_active = True
        w.receiving = False
        w.incoming_radio_id = "endpoint"
        w.receive_offer_active = False
        w.send_started = False
        w.attempt_id = "attempt"
        w.pending_radio_id = "endpoint"
        w.pending_peer = None
        w.paths = ["file"]
        w.radio_peers = {}
        w.scan_pending = False
        w.radio_ready = True
        w.selected_endpoint = {"name": "Laptop", "port": 63151, "device_id": "peer", "public_key": "key"}
        w.refresh_nearby_devices = Mock()
        w.set_busy = Mock()
        self.event = {"event": "wifi_direct_connected", "id": "endpoint", "attempt_id": "attempt",
                      "local_address": "192.168.137.2", "remote_address": "192.168.137.1"}

    def test_advertised_port_snapshot_and_single_send(self):
        self.window.radio_peers["endpoint"] = {"port": 22602}
        self.window.handle_wifi_connected(self.event)
        self.window.handle_wifi_connected(self.event)
        self.window.network.send_files.assert_called_once()
        args, kwargs = self.window.network.send_files.call_args
        self.assertEqual(args[0].port, 63151)
        self.assertEqual(kwargs["local_address"], "192.168.137.2")
        self.assertEqual(kwargs["expected_public_key"], "key")

    def test_old_attempt_cannot_restart_send(self):
        self.window.handle_wifi_connected({**self.event, "attempt_id": "expired"})
        self.window.network.send_files.assert_not_called()

    def test_incoming_link_never_sends_staged_files(self):
        self.window.workflow_active = False
        self.window.receiving = True
        self.window.handle_wifi_connected({**self.event, "attempt_id": None})
        self.window.network.send_files.assert_not_called()

    def test_failed_scan_releases_pending_flag(self):
        self.window.scan_pending = True
        self.window.workflow_active = False
        self.window.handle_radio_event({"event": "wifi_direct_scan_error", "message": "adapter unavailable"})
        self.window.scan_radios()
        self.window.radio.scan_wifi_direct.assert_called_once()

    def test_missing_metadata_does_not_overwrite_valid_peer(self):
        self.window.radio_peers["endpoint"] = {"port": 63151}
        self.window.handle_radio_event({"event": "wifi_direct_peer", "id": "endpoint", "port": 0})
        self.assertEqual(self.window.radio_peers["endpoint"]["port"], 63151)

    def test_blocked_peer_cannot_send(self):
        self.window.store.peer.return_value = {"blocked": True, "public_key": "key"}
        self.window.reset_workflow = Mock()
        self.window.handle_wifi_connected(self.event)
        self.window.network.send_files.assert_not_called()
        self.window.reset_workflow.assert_called_once()

    def test_duplicate_identity_is_one_entry(self):
        self.window.radio_peers["old"] = {"device_id": "peer"}
        self.window.handle_radio_event({"event": "wifi_direct_peer", "id": "new", "port": 63151,
            "device_id": "peer", "public_key": base64.urlsafe_b64encode(b"x" * 32).decode()})
        self.assertEqual(list(self.window.radio_peers), ["new"])
