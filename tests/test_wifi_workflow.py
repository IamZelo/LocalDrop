import base64
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
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
        w.start_refresh_animation = Mock()
        w.finish_refresh_animation = Mock()
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

    def test_refresh_updates_lan_and_starts_available_radio_scan(self):
        self.window.workflow_active = False
        self.window.receiving = False
        self.window.discovery = Mock()
        self.window.scan_radios = Mock()
        self.window.refresh_devices()
        self.window.discovery.refresh.assert_called_once_with()
        self.window.refresh_nearby_devices.assert_called_once_with()
        self.window.scan_radios.assert_called_once_with()

    def test_refresh_is_ignored_during_transfer(self):
        self.window.discovery = Mock()
        self.window.scan_radios = Mock()
        self.window.refresh_devices()
        self.window.discovery.refresh_registration.assert_not_called()
        self.window.scan_radios.assert_not_called()

    def test_device_click_requires_staged_files(self):
        item = Mock()
        item.data.return_value = "lan:peer"
        self.window.paths = []
        self.window.workflow_active = False
        self.window.device_clicked(item)
        self.window.network.send_files.assert_not_called()
        self.window.status.setText.assert_called_with("Drop or add files before selecting a device.")

    def test_offline_trusted_device_can_be_revoked(self):
        item = Mock()
        item.data.side_effect = lambda role: {
            app.DEVICE_TRUSTED_ROLE: True,
            app.DEVICE_ID_ROLE: "peer",
        }.get(role)
        self.window.devices = Mock()
        self.window.devices.itemAt.return_value = item
        menu = Mock()
        rename_action, revoke_action = object(), object()
        menu.addAction.side_effect = [rename_action, revoke_action]
        menu.exec.return_value = revoke_action
        app.QMessageBox.Yes = 1
        app.QMessageBox.No = 2
        app.QMessageBox.question = Mock(return_value=1)
        with patch.object(app, "QMenu", return_value=menu):
            self.window.show_device_menu(Mock())
        self.window.store.revoke_trust.assert_called_once_with("peer")
        self.window.refresh_nearby_devices.assert_called_once_with()

    def test_receive_progress_populates_live_details(self):
        for name in ("receive_file_label", "receive_summary_label", "receive_rate_label",
                     "receive_details"):
            setattr(self.window, name, Mock())
        progress = SimpleNamespace(
            direction="receive", percent=50, current_file="movie.mp4", file_index=2,
            total_files=4, files_completed=1, bytes_transferred=512,
            total_bytes=1024, bytes_per_second=256, eta_seconds=2,
        )
        app.MainWindow.update_progress(self.window, progress)
        self.window.progress.setValue.assert_called_once_with(50)
        self.window.receive_file_label.setText.assert_called_once_with(
            "Receiving movie.mp4  ·  File 2 of 4"
        )
        self.window.receive_summary_label.setText.assert_called_once_with(
            "1 of 4 files complete  ·  512 B of 1.0 KB  ·  50%"
        )
        self.window.receive_rate_label.setText.assert_called_once_with(
            "256 B/s  ·  2s remaining"
        )
        self.window.receive_details.show.assert_called_once_with()

    def test_receive_status_has_ready_and_busy_states(self):
        self.window.receive_status = Mock()
        app.MainWindow.update_receive_status(self.window, "ready")
        self.window.receive_status.setText.assert_called_with("●  Ready to receive")
        app.MainWindow.update_receive_status(self.window, "busy")
        self.window.receive_status.setText.assert_called_with("●  Transfer in progress")

    def test_trusted_device_can_be_renamed(self):
        item = Mock()
        item.data.side_effect = lambda role: {
            app.DEVICE_TRUSTED_ROLE: True,
            app.DEVICE_ID_ROLE: "peer",
        }.get(role)
        self.window.devices = Mock()
        self.window.devices.itemAt.return_value = item
        self.window.store.peer.return_value = {"name": "Office Laptop"}
        menu = Mock()
        rename_action, revoke_action = object(), object()
        menu.addAction.side_effect = [rename_action, revoke_action]
        menu.exec.return_value = rename_action
        app.QInputDialog.getText = Mock(return_value=("Harsh's PC", True))
        with patch.object(app, "QMenu", return_value=menu):
            self.window.show_device_menu(Mock())
        self.window.store.rename_peer.assert_called_once_with("peer", "Harsh's PC")
        self.window.refresh_nearby_devices.assert_called_once_with()

    def test_current_device_profile_name_updates_live_services(self):
        previous = Mock(display_name="Old Name")
        updated = Mock(display_name="My Laptop")
        self.window.identity = previous
        self.window.profile_name = Mock()
        self.window.discovery = Mock()
        self.window.radio = Mock()
        self.window.workflow_active = False
        self.window.receiving = False
        app.QInputDialog.getText = Mock(return_value=("My Laptop", True))
        app.update_display_name = Mock(return_value=updated)
        app.MainWindow.edit_profile(self.window)
        self.assertIs(self.window.identity, updated)
        self.assertIs(self.window.network.identity, updated)
        self.window.profile_name.setText.assert_called_once_with("My Laptop")
        self.window.discovery.update_display_name.assert_called_once_with("My Laptop")
        self.window.radio.update_display_name.assert_called_once_with("My Laptop")

    def test_cancel_without_active_socket_resets_radio_negotiation(self):
        self.window.cancel_button = Mock()
        self.window.network.cancel_active_transfer.return_value = False
        self.window.reset_workflow = Mock()
        app.MainWindow.cancel_transfer(self.window)
        self.window.cancel_button.setEnabled.assert_called_once_with(False)
        self.window.network.cancel_active_transfer.assert_called_once_with()
        self.window.reset_workflow.assert_called_once_with()

    def test_auto_accepted_receive_enters_busy_state(self):
        self.window.workflow_active = False
        self.window.receiving = False
        app.MainWindow.begin_receive(self.window)
        self.assertTrue(self.window.receiving)
        self.window.set_busy.assert_called_once_with(True)

    def test_receive_completion_is_shown_after_workflow_reset(self):
        self.window.receiving = True
        self.window.reset_workflow = Mock()
        completion = SimpleNamespace(
            file_count=2,
            sender_name="Office Laptop",
            destination=r"C:\Users\User\Downloads\Local Secure Share\Office Laptop",
        )

        app.MainWindow.finish_receive(self.window, completion)

        self.window.reset_workflow.assert_called_once_with(reset_link=False)
        self.window.status.setText.assert_called_once_with(
            "Received 2 files from Office Laptop. Saved to "
            r"C:\Users\User\Downloads\Local Secure Share\Office Laptop."
        )

    def test_successful_send_shows_file_and_elapsed_time(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.pdf"
            path.write_bytes(b"content")
            self.window.paths = [path]
            self.window.selected_endpoint = {"name": "Office Laptop"}
            self.window.send_started_at = 10.0
            self.window.finish_transfer = Mock()
            app.QMessageBox.information = Mock()

            with patch.object(app.time, "monotonic", return_value=14.2):
                app.MainWindow.finish_transfer_result(
                    self.window, SimpleNamespace(succeeded=True)
                )

        app.QMessageBox.information.assert_called_once_with(
            self.window,
            "Files sent",
            "report.pdf (7 B) sent to Office Laptop in 4 seconds.",
        )
        self.window.finish_transfer.assert_called_once_with(True)

    def test_failed_send_does_not_show_success_popup(self):
        self.window.finish_transfer = Mock()
        app.QMessageBox.information = Mock()
        result = SimpleNamespace(succeeded=False, cancelled=True)

        app.MainWindow.finish_transfer_result(self.window, result)

        app.QMessageBox.information.assert_not_called()
        self.window.finish_transfer.assert_called_once_with(False)

    def test_refresh_animation_restores_button(self):
        self.window.refresh_in_progress = True
        self.window.refresh_animation_timer = Mock()
        self.window.refresh_button = Mock()
        self.window.refresh_base_icon = object()
        self.window.workflow_active = False
        self.window.receiving = False
        app.MainWindow.finish_refresh_animation(self.window)
        self.assertFalse(self.window.refresh_in_progress)
        self.window.refresh_animation_timer.stop.assert_called_once_with()
        self.window.refresh_button.setIcon.assert_called_once_with(self.window.refresh_base_icon)
        self.window.refresh_button.setEnabled.assert_called_once_with(True)
