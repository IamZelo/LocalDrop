import tempfile
import threading
import time
import unittest
import hashlib
import uuid
from pathlib import Path
from unittest.mock import ANY, Mock, patch
from radio_test_support import Peer, load

network = load("network")

class InlineThread:
    def __init__(self, target, **kwargs):
        self.target = target
    def start(self):
        self.target()

class DeferredThread:
    latest = None
    def __init__(self, target, **kwargs):
        self.target = target
        DeferredThread.latest = self
    def start(self):
        pass

class NetworkTransferTests(unittest.TestCase):
    def setUp(self):
        self.manager = object.__new__(network.NetworkManager)
        m = self.manager
        m._send_lock = threading.Lock()
        m._transfer_state_lock = threading.Lock()
        m._send_cancel_event = None
        m._receive_cancel_event = None
        m._send_socket = None
        m._receive_socket = None
        m.identity = Mock(device_id="sender", display_name="Sender", public_b64="public")
        m.identity.sign.return_value = "signature"
        m.store = Mock()
        m.store.peer.return_value = None
        m.callbacks = Mock()
        self.sock = Mock()
        m._connect = Mock(return_value=self.sock)
        self.peer = Peer("radio:endpoint", "192.168.137.1", 63151, "receiver", "Receiver")

    def test_approval_and_stream_have_separate_timeouts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.txt"
            path.write_bytes(b"file contents")
            with patch.object(network.threading, "Thread", InlineThread), patch.object(network, "recv_frame", side_effect=[
                ("json", {"accepted": True}), ("json", {"status": "complete"})]):
                self.manager.send_files(self.peer, [path], expected_public_key="key", local_address="192.168.137.2")
        self.assertEqual([c.args[0] for c in self.sock.settimeout.call_args_list],
                         [network.APPROVAL_TIMEOUT, network.STREAM_TIMEOUT])
        self.assertGreater(network.APPROVAL_TIMEOUT, 300)
        self.manager.callbacks.transfer_finished.assert_called_once_with(True)
        self.manager.callbacks.trust_changed.assert_called_once_with()
        self.manager._connect.assert_called_once_with(
            self.peer, "key", timeout=8, local_address="192.168.137.2",
            cancel_event=ANY,
        )
        self.assertFalse(self.manager._send_lock.locked())

    def test_decline_does_not_send_file_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.txt"
            path.write_bytes(b"file contents")
            with patch.object(network.threading, "Thread", InlineThread), patch.object(network, "recv_frame", return_value=("json", {"accepted": False, "reason": "Transfer declined"})), patch.object(network, "send_chunk") as send_chunk:
                self.manager.send_files(self.peer, [path], expected_public_key="key")
                send_chunk.assert_not_called()
        self.manager.callbacks.transfer_finished.assert_called_once_with(False)
        self.manager.store.trust_peer.assert_not_called()

    def test_parallel_send_is_rejected(self):
        self.manager._send_lock.acquire()
        self.manager.send_files(self.peer, [])
        self.manager._connect.assert_not_called()

    def test_connect_error_reports_phase_and_closes_socket(self):
        del self.manager._connect
        raw = Mock()
        raw.connect.side_effect = TimeoutError("timed out")
        with patch.object(network.socket, "socket", return_value=raw):
            with self.assertRaisesRegex(network.NetworkError, "tcp_connect.*63151"):
                self.manager._connect(self.peer, "key", local_address="192.168.137.2")
        raw.bind.assert_called_once_with(("192.168.137.2", 0))
        raw.close.assert_called_once()

    def test_incoming_route_reports_transport(self):
        manager = object.__new__(network.NetworkManager)
        manager.running = True
        manager._link_condition = threading.Condition()
        manager._authorizations = {
            ("192.168.1.4", "session"): network.RouteAuthorization(
                "192.168.1.4", network.Transport.LAN, "session", time.monotonic() + 30
            )
        }
        manager._receive_lock = threading.Lock()
        manager._transfer_state_lock = threading.Lock()
        manager._send_cancel_event = None
        manager._receive_cancel_event = None
        manager._send_socket = None
        manager._receive_socket = None
        manager.callbacks = Mock()
        manager._receive_files = Mock()
        wrapped = Mock()
        manager._server_context = Mock()
        manager._server_context.wrap_socket.return_value = wrapped
        raw = Mock()
        raw.getsockname.return_value = ("192.168.1.2", 63151)
        with patch.object(network, "recv_frame", return_value=("json", {"type": "offer"})):
            manager._handle_client(raw, ("192.168.1.4", 52000))
        manager.callbacks.route_started.assert_called_once_with(network.Transport.LAN)

    def test_progress_tracker_reports_speed_eta_and_file_completion(self):
        updates = []
        with patch.object(network.time, "monotonic", side_effect=[0.0, 0.0, 1.0, 2.0]):
            tracker = network._ProgressTracker(updates.append, "transfer", "receive", 1000, 2)
            tracker.update(0, "one.txt", 1, 0, force=True)
            tracker.update(500, "one.txt", 1, 0, force=True)
            tracker.update(1000, "two.txt", 2, 2, force=True)
        middle = updates[1]
        self.assertEqual(middle.percent, 50)
        self.assertEqual(middle.bytes_per_second, 500)
        self.assertEqual(middle.eta_seconds, 1)
        self.assertEqual(updates[-1].files_completed, 2)
        self.assertEqual(updates[-1].percent, 100)

    def test_progress_tracker_throttles_non_boundary_updates(self):
        updates = []
        with patch.object(network.time, "monotonic", side_effect=[0.0, 0.0, 0.1, 0.21]):
            tracker = network._ProgressTracker(updates.append, "transfer", "receive", 100, 1)
            tracker.update(0, "file.txt", 1, 0, force=True)
            tracker.update(10, "file.txt", 1, 0)
            tracker.update(21, "file.txt", 1, 0)
        self.assertEqual(len(updates), 2)
        self.assertEqual(updates[-1].bytes_transferred, 21)

    def test_user_cancel_is_terminal_and_does_not_penalize_route(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.txt"
            path.write_bytes(b"file contents")
            with patch.object(network.threading, "Thread", DeferredThread):
                self.manager.send_files(self.peer, [path], expected_public_key="key")
            self.assertTrue(self.manager.cancel_active_transfer())
            DeferredThread.latest.target()
        result = self.manager.callbacks.result_finished.call_args.args[0]
        self.assertTrue(result.cancelled)
        self.assertFalse(result.may_fallback)
        self.manager.store.record_route.assert_not_called()
        self.assertFalse(self.manager._send_lock.locked())

    def test_cancel_closes_active_socket(self):
        active = Mock()
        event = threading.Event()
        self.manager._receive_cancel_event = event
        self.manager._receive_socket = active
        self.assertTrue(self.manager.cancel_active_transfer())
        self.assertTrue(event.is_set())
        active.shutdown.assert_called_once_with(network.socket.SHUT_RDWR)
        active.close.assert_called_once_with()

    def test_cancel_receive_keeps_verified_files_and_removes_partial(self):
        cancel_event = threading.Event()
        with tempfile.TemporaryDirectory() as directory:
            self.manager.store.peer.return_value = {
                "device_id": "sender", "name": "Sender", "public_key": "public",
                "blocked": False, "auto_accept": False,
            }
            self.manager.callbacks.accept_transfer.return_value = network.TransferApproval(directory)
            first, second = b"first", b"second"
            offer = {
                "type": "offer", "signature": "signature", "time": int(time.time()),
                "transfer_id": uuid.uuid4().hex,
                "sender": {"device_id": "sender", "name": "Sender", "public_key": "public"},
                "files": [
                    {"name": "one.txt", "size": len(first), "sha256": hashlib.sha256(first).hexdigest()},
                    {"name": "two.txt", "size": len(second), "sha256": hashlib.sha256(second).hexdigest()},
                ],
            }
            frames = iter([
                ("json", {"type": "file_start", "index": 0}),
                ("chunk", first),
                ("json", {"type": "file_end", "index": 0}),
                ("json", {"type": "file_start", "index": 1}),
            ])
            def receive_frame(_sock):
                try:
                    return next(frames)
                except StopIteration:
                    cancel_event.set()
                    return "chunk", second
            with patch.object(network, "recv_frame", side_effect=receive_frame):
                with self.assertRaises(network.TransferCancelled):
                    self.manager._receive_files(self.sock, offer, cancel_event)
            self.assertEqual((Path(directory) / "one.txt").read_bytes(), first)
            self.assertFalse((Path(directory) / "two.txt").exists())
            self.assertFalse((Path(directory) / "two.txt.part").exists())

    def test_auto_accepted_receive_returns_completion_details(self):
        payload = b"file contents"
        self.manager.store.peer.return_value = {
            "device_id": "sender", "name": "Sender", "public_key": "public",
            "blocked": False, "auto_accept": True,
        }
        offer = {
            "type": "offer", "signature": "signature", "time": int(time.time()),
            "transfer_id": uuid.uuid4().hex,
            "sender": {"device_id": "sender", "name": "Sender", "public_key": "public"},
            "files": [{
                "name": "example.txt", "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }],
        }
        frames = [
            ("json", {"type": "file_start", "index": 0}),
            ("chunk", payload),
            ("json", {"type": "file_end", "index": 0}),
            ("json", {"type": "transfer_end"}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            with patch.object(network, "_automatic_destination", return_value=destination), \
                    patch.object(network, "recv_frame", side_effect=frames):
                completion = self.manager._receive_files(self.sock, offer)

            self.assertEqual((destination / "example.txt").read_bytes(), payload)

        self.assertEqual(completion, network.ReceiveCompletion(
            "Sender", 1, len(payload), str(destination)
        ))
        self.manager.callbacks.accept_transfer.assert_not_called()
