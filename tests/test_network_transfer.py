import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from radio_test_support import Peer, load

network = load("network")

class InlineThread:
    def __init__(self, target, **kwargs):
        self.target = target
    def start(self):
        self.target()

class NetworkTransferTests(unittest.TestCase):
    def setUp(self):
        self.manager = object.__new__(network.NetworkManager)
        m = self.manager
        m._send_lock = threading.Lock()
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
        self.manager._connect.assert_called_once_with(self.peer, "key", local_address="192.168.137.2")
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
