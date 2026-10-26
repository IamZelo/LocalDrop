from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, QStandardPaths, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from qasync import QEventLoop

from .discovery import DiscoveredPeer
try:  # lightweight test boundaries may expose only the peer record
    from .discovery import Discovery
except ImportError:  # pragma: no cover - used by isolated UI tests
    Discovery = None  # type: ignore[misc,assignment]
from .connectivity import Transport
from .identity import load_or_create_identity, unb64
from .native_radio import NativeRadio
from .network import InteractionCallbacks, NetworkManager
from .storage import LocalStore

logger = logging.getLogger("secure_share.app")


@dataclass
class Request:
    payload: object
    event: threading.Event = field(default_factory=threading.Event)
    result: object = None


class UiBridge(QObject):
    status_changed = Signal(str)
    progress_changed = Signal(str, int)
    transfer_offer = Signal(object)
    transfer_finished = Signal(bool)
    transfer_result = Signal(object)
    receive_finished = Signal()
    radio_event = Signal(object)
    discovery_changed = Signal(object)

    def _wait(self, signal: Signal, payload: object, timeout: int = 300):
        request = Request(payload)
        signal.emit(request)
        if not request.event.wait(timeout):
            request.event.set()
            return None
        return request.result



    def accept_transfer(self, peer: dict, files: list[dict]) -> str | None:
        result = self._wait(self.transfer_offer, (peer, files))
        return str(result) if result else None


class DropList(QListWidget):
    files_dropped = Signal(object)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setSelectionMode(QListWidget.ExtendedSelection)
        self.setMinimumHeight(150)
        self.setStyleSheet(
            "QListWidget { border: 2px dashed #8a8f98; border-radius: 10px; padding: 12px; }"
            "QListWidget:focus { border-color: #3478f6; }"
        )

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls() and any(url.isLocalFile() for url in event.mimeData().urls()):
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:
        event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]
        self.files_dropped.emit([path for path in paths if path.is_file()])
        event.acceptProposedAction()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Local Secure Share")
        self.resize(620, 680)

        self.identity = load_or_create_identity()
        self.store = LocalStore(self.identity.device_id)
        self.bridge = UiBridge()
        callbacks = InteractionCallbacks(
            self.bridge.accept_transfer,
            self.bridge.status_changed.emit,
            self.bridge.progress_changed.emit,
            lambda _succeeded: None,
            receive_finished=self.bridge.receive_finished.emit,
            result_finished=self.bridge.transfer_result.emit,
        )
        self.network = NetworkManager(self.identity, self.store, callbacks)
        self.radio_peers: dict[str, dict] = {}
        self.lan_peers: dict[str, DiscoveredPeer] = {}
        self.radio_ready = False
        self.receiving = False
        self.incoming_radio_id = None
        self.receive_offer_active = False
        self.attempt_id = None
        self.selected_endpoint = None
        self.send_started = False
        self.paths: list[Path] = []
        self.workflow_active = False
        self.pending_radio_id: str | None = None
        self.pending_peer: DiscoveredPeer | None = None
        self.scan_pending = False

        self._build_ui()
        self._connect_signals()

        # LAN discovery is independent of WinRT and starts before the radio.
        self.discovery = Discovery(self.identity.device_id, self.identity.display_name,
                                   self.network.port, self.identity.public_b64,
                                   self.bridge.discovery_changed.emit)

        self.radio = NativeRadio(
            self.identity.device_id,
            self.network.port,
            self.bridge.radio_event.emit,
            public_key=self.identity.public_b64,
        )
        self.scan_timer = QTimer(self)
        self.scan_timer.setInterval(12000)
        self.scan_timer.timeout.connect(self.scan_radios)
        self.expiry_timer = QTimer(self)
        self.expiry_timer.setInterval(5000)
        self.expiry_timer.timeout.connect(self.prune_nearby_devices)
        self.expiry_timer.start()
        if self.radio.start():
            self.status.setText("Starting Wi-Fi Direct...")
            self.scan_timer.start()
        else:
            self.status.setText("Wi-Fi Direct unavailable. Run: python -m secure_share.diagnostics")

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(10)

        title = QLabel("Local Secure Share")
        title.setStyleSheet("font-size: 25px; font-weight: 650")
        root.addWidget(title)
        subtitle = QLabel(f"{self.identity.display_name} | LAN + nearby wireless | Windows")
        subtitle.setStyleSheet("color: #666")
        root.addWidget(subtitle)

        root.addWidget(QLabel("1. Drop files"))
        self.file_list = DropList()
        self.file_list.setToolTip("Drop regular files here; folders are not transferred")
        root.addWidget(self.file_list)
        file_actions = QHBoxLayout()
        self.add_button = QPushButton("Add files")
        self.remove_button = QPushButton("Remove selected")
        file_actions.addWidget(self.add_button)
        file_actions.addWidget(self.remove_button)
        file_actions.addStretch()
        root.addLayout(file_actions)

        device_header = QHBoxLayout()
        device_header.addWidget(QLabel("2. Click a nearby device to send"))
        device_header.addStretch()
        self.radio_status = QLabel("Wi-Fi starting...")
        self.radio_status.setStyleSheet("color: #666")
        device_header.addWidget(self.radio_status)
        root.addLayout(device_header)

        self.devices = QListWidget()
        self.devices.setMinimumHeight(210)
        self.devices.setStyleSheet("QListWidget::item { padding: 12px; } QListWidget::item:selected { border-radius: 6px; }")
        root.addWidget(self.devices)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        root.addWidget(self.progress)
        self.status = QLabel("No internet or cloud service is used.")
        self.status.setWordWrap(True)
        root.addWidget(self.status)

        hint = QLabel("The receiver must accept the file offer before any file data is sent.")
        hint.setStyleSheet("color: #666; font-size: 11px")
        root.addWidget(hint)
        if self.identity.fallback_storage:
            warning = QLabel("Warning: the OS keychain is unavailable; identity keys use local file permissions.")
            warning.setWordWrap(True)
            warning.setStyleSheet("color: #a55b00")
            root.addWidget(warning)
        self.setCentralWidget(central)

    def _connect_signals(self) -> None:
        self.bridge.status_changed.connect(self.status.setText)
        self.bridge.progress_changed.connect(self.update_progress)
        self.bridge.transfer_offer.connect(self.confirm_transfer)
        self.bridge.transfer_finished.connect(self.finish_transfer)
        self.bridge.transfer_result.connect(self.finish_transfer_result)
        self.bridge.receive_finished.connect(self.finish_receive)
        self.bridge.radio_event.connect(self.handle_radio_event)
        self.bridge.discovery_changed.connect(self.handle_discovery)
        self.file_list.files_dropped.connect(self.add_paths)
        self.add_button.clicked.connect(self.pick_files)
        self.remove_button.clicked.connect(self.remove_files)
        self.devices.itemClicked.connect(self.device_clicked)

    @Slot(object)
    def add_paths(self, paths: list[Path]) -> None:
        if self.workflow_active or self.receiving:
            return
        existing = {str(path.resolve()) for path in self.paths}
        for path in paths:
            if path.is_file() and str(path.resolve()) not in existing:
                self.paths.append(path)
                self.file_list.addItem(f"{path.name}  ({path.stat().st_size:,} bytes)")
                existing.add(str(path.resolve()))
        if self.paths:
            self.status.setText("Files ready. Click a nearby device to send.")

    def pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files")
        self.add_paths([Path(value) for value in files])

    def remove_files(self) -> None:
        if self.workflow_active or self.receiving:
            return
        rows = sorted((self.file_list.row(item) for item in self.file_list.selectedItems()), reverse=True)
        for row in rows:
            self.file_list.takeItem(row)
            self.paths.pop(row)

    def set_busy(self, busy: bool) -> None:
        self.devices.setEnabled(not busy)
        self.add_button.setEnabled(not busy)
        self.remove_button.setEnabled(not busy)
        self.file_list.setEnabled(not busy)

    @Slot(QListWidgetItem)
    def device_clicked(self, item: QListWidgetItem) -> None:
        radio_id = item.data(Qt.UserRole)
        if not radio_id or self.workflow_active or self.receiving:
            return
        if not self.paths:
            self.status.setText("Drop or add files before selecting a device.")
            return
        if str(radio_id).startswith("lan:"):
            peer = getattr(self, "lan_peers", {}).get(str(radio_id)[4:])
            if not peer:
                self.status.setText("Device no longer available. Waiting for a fresh LAN announcement.")
                return
            self.workflow_active, self.send_started = True, True
            self.attempt_id = uuid.uuid4().hex
            self.selected_endpoint = {"device_id": peer.device_id, "name": peer.display_name,
                                      "public_key": peer.public_key, "route": "lan"}
            self.set_busy(True)
            self.progress.setRange(0, 0)
            self.status.setText(f"Same network: connecting to {peer.display_name}...")
            self.network.send_files(peer, list(self.paths), expected_public_key=peer.public_key,
                                    local_address=peer.local_interface)
            return
        peer = self.radio_peers.get(radio_id)
        if not peer:
            self.status.setText("Device no longer available. Waiting for a fresh scan.")
            return
        self.attempt_id = uuid.uuid4().hex
        self.selected_endpoint = dict(peer)
        self.pending_radio_id = radio_id
        self.pending_peer = None
        self.send_started = False
        self.workflow_active = True
        self.set_busy(True)
        self.progress.setRange(0, 0)
        self.scan_timer.stop()
        self.status.setText(f"Connecting to {peer['name']} over Wi-Fi Direct...")
        try:
            self.radio.connect_wifi_direct(radio_id, self.attempt_id)
        except RuntimeError as exc:
            self.status.setText(f"Connection failed: {exc}")
            self.reset_workflow()

    def scan_radios(self) -> None:
        if not self.radio_ready or self.scan_pending or self.workflow_active or self.receiving:
            return
        self.scan_pending = True
        self.radio_status.setText("Scanning Wi-Fi Direct...")
        try:
            self.radio.scan_wifi_direct()
        except RuntimeError as exc:
            self.scan_pending = False
            self.radio_status.setText(f"Scan unavailable: {exc}")

    @Slot(object)
    def handle_radio_event(self, event: dict) -> None:
        kind = event.get("event", "")
        if "error" in kind or kind == "fatal":
            logger.error("Radio event: %s", event)
        else:
            logger.info("Radio event: %s", event)
        if kind == "ready":
            self.radio_ready = True
            self.radio_status.setText("Wi-Fi Direct ready")
            self.status.setText("Searching for nearby computers. Keep the app open on both devices.")
            self.scan_timer.start()
            self.scan_radios()
        elif kind == "wifi_direct_peer":
            try:
                if not event.get("device_id") or not 0 < int(event["port"]) < 65536 or len(unb64(event["public_key"])) != 32:
                    raise ValueError("Incomplete discovery metadata")
            except (KeyError, ValueError, TypeError):
                logger.warning("Ignoring incomplete Wi-Fi Direct endpoint %s", event.get("id"))
                return
            if event["device_id"] == self.identity.device_id:
                return
            # Deduplicate by app identity, never by hostname.
            for key, existing in list(self.radio_peers.items()):
                if existing["device_id"] == event["device_id"] and key != event["id"]:
                    del self.radio_peers[key]
            self.radio_peers[event["id"]] = {**event, "seen_at": time.monotonic()}
            self.refresh_nearby_devices()
        elif kind == "wifi_direct_scan_complete":
            self.scan_pending = False
            self.radio_status.setText(f"{len(self.radio_peers)} nearby")
            self.refresh_nearby_devices()
        elif kind == "wifi_direct_scan_error":
            self.scan_pending = False
            self.radio_status.setText("Scan failed; retrying")
            if not self.workflow_active and not self.receiving:
                self.status.setText(f"Discovery failed: {event.get('message')}. Retrying automatically.")
        elif kind == "wifi_direct_connection_request":
            event["accepted"] = not self.workflow_active and not self.receiving
            if event["accepted"]:
                self.receiving = True
                self.incoming_radio_id = event.get("id")
                self.scan_timer.stop()
                self.set_busy(True)
                self.progress.setRange(0, 0)
                self.status.setText(f"Connecting incoming sender {event.get('name')}...")
                logger.info("Accepted incoming Wi-Fi Direct request from %s; waiting for Windows endpoint", event.get("name"))
            event["_decision"].set()
        elif kind == "wifi_direct_connected":
            self.handle_wifi_connected(event)
        elif kind == "wifi_direct_pairing_ceremony":
            if self.workflow_active or self.receiving:
                self.status.setText("Negotiating the Wi-Fi Direct connection with Windows...")
        elif kind == "wifi_direct_status":
            state = str(event.get("status", ""))
            if state == "ABORTED":
                self.radio_ready = False
                self.radio_status.setText("Wi-Fi Direct unavailable")
                self.status.setText(f"Windows stopped Wi-Fi Direct: {event.get('error')}. Check Wi-Fi and adapter drivers.")
            elif state == "STARTED":
                self.radio_ready = True
                self.radio_status.setText("Wi-Fi Direct ready")
            elif not self.workflow_active and not self.receiving:
                self.radio_status.setText(f"Wi-Fi Direct: {state.lower()}")
        elif kind in ("wifi_direct_error", "error", "fatal"):
            if event.get("attempt_id") and event["attempt_id"] != self.attempt_id:
                return
            self.status.setText(f"{event.get('phase', 'Radio')}: {event.get('message', 'Connection failed')}")
            if kind == "fatal":
                self.radio_ready = False
                self.radio_status.setText("Wi-Fi Direct unavailable")
            self.reset_workflow()
        elif kind == "wifi_direct_connection_status" and event.get("status") == "DISCONNECTED":
            self.network.clear_links()
            # Active socket operations report their own error with the transfer phase.
            if self.receiving and not self.receive_offer_active and event.get("id") == self.incoming_radio_id:
                self.status.setText("Sender disconnected. Waiting for another connection.")
                self.reset_workflow()

    def refresh_nearby_devices(self) -> None:
        self.devices.clear()
        lan_ids = set()
        for device_id, peer in sorted(getattr(self, "lan_peers", {}).items(), key=lambda entry: entry[1].display_name):
            item = QListWidgetItem(f"{peer.display_name}  |  Same network")
            item.setData(Qt.UserRole, f"lan:{device_id}")
            self.devices.addItem(item)
            lan_ids.add(device_id)
        for radio_id, peer in sorted(self.radio_peers.items(), key=lambda entry: entry[1].get("name", "")):
            if peer.get("device_id") in lan_ids:
                continue
            item = QListWidgetItem(f"{peer.get('name') or 'Nearby computer'}  |  Wi-Fi Direct")
            item.setData(Qt.UserRole, radio_id)
            self.devices.addItem(item)
        if not self.radio_peers and not getattr(self, "lan_peers", {}):
            item = QListWidgetItem("No nearby computers yet. Keep Wi-Fi and this app on on both PCs.")
            item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            self.devices.addItem(item)

    def prune_nearby_devices(self) -> None:
        if self.workflow_active or self.receiving:
            return
        cutoff = time.monotonic() - 60
        self.radio_peers = {key: peer for key, peer in self.radio_peers.items() if peer["seen_at"] >= cutoff}
        if hasattr(self, "discovery"):
            self.discovery.refresh_registration()
            self.discovery.prune()
        self.refresh_nearby_devices()

    @Slot(object)
    def handle_discovery(self, peers: list[DiscoveredPeer]) -> None:
        self.lan_peers = {peer.device_id: peer for peer in peers}
        for peer in peers:
            # Discovery metadata is necessary but transfer authentication still
            # occurs through signed offers and pinned TLS.
            self.network.authorize_route(peer.host, Transport.LAN, f"mdns:{peer.device_id}", ttl=60)
        self.refresh_nearby_devices()

    def handle_wifi_connected(self, event: dict) -> None:
        if ":" in event.get("remote_address", ""):
            return
        if not event.get("attempt_id"):
            if self.receiving:
                self.network.register_link(event["local_address"], event["remote_address"])
                self.status.setText("Wi-Fi Direct connected. Waiting for the sender's file offer...")
                QTimer.singleShot(330000, lambda endpoint=self.incoming_radio_id: self.incoming_offer_timeout(endpoint))
            return
        if (not self.workflow_active or event.get("attempt_id") != self.attempt_id
                or self.send_started or event.get("id", "").casefold() != self.pending_radio_id.casefold()):
            logger.info("Ignoring duplicate or expired connection event: %s", event)
            return
        self.network.register_link(event["local_address"], event["remote_address"])
        peer = self.selected_endpoint
        trusted = self.store.peer(peer["device_id"])
        if trusted and (trusted["blocked"] or trusted["public_key"] != peer["public_key"]):
            self.status.setText("Device blocked or its identity changed. Transfer stopped.")
            self.reset_workflow()
            return
        self.pending_peer = DiscoveredPeer(
            f"radio:{self.pending_radio_id}", event["remote_address"], int(peer["port"]),
            peer["device_id"], peer.get("name") or "Nearby computer",
        )
        self.send_started = True
        self.network.send_files(self.pending_peer, list(self.paths),
                                expected_public_key=peer["public_key"], local_address=event["local_address"])



    def incoming_offer_timeout(self, endpoint: str) -> None:
        if self.receiving and not self.receive_offer_active and self.incoming_radio_id == endpoint:
            self.status.setText("No file offer arrived within 5 minutes. Ask the sender to retry.")
            self.reset_workflow()

    @Slot(object)
    def confirm_transfer(self, request: Request) -> None:
        if self.workflow_active or request.event.is_set():
            request.event.set()
            return
        peer, files = request.payload
        self.receiving = True
        self.receive_offer_active = True
        self.set_busy(True)
        self.status.setText(f"Awaiting your approval for files from {peer['name']}.")
        def readable_size(size: int) -> str:
            value = float(size)
            for unit in ("B", "KB", "MB", "GB", "TB"):
                if value < 1024 or unit == "TB":
                    return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
                value /= 1024
            return f"{size:,} B"

        descriptions = "\n".join(
            f"• {item['name']} — {readable_size(int(item['size']))}" for item in files
        )
        total = readable_size(sum(int(item["size"]) for item in files))
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Incoming files")
        dialog.setIcon(QMessageBox.Question)
        dialog.setText(
            f"{peer['name']} wants to send:\n\n{descriptions}\n\n"
            f"Total: {total}\nSave to Downloads?"
        )
        accept_button = dialog.addButton("Accept", QMessageBox.AcceptRole)
        dialog.addButton("Deny", QMessageBox.RejectRole)
        QTimer.singleShot(300000, dialog.reject)
        dialog.exec()
        if dialog.clickedButton() is accept_button and not request.event.is_set():
            downloads = QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
            destination = Path(downloads) if downloads else Path.home() / "Downloads"
            destination.mkdir(parents=True, exist_ok=True)
            request.result = str(destination)
            self.status.setText("Accepted. Receiving files into Downloads...")
        else:
            self.status.setText("Transfer declined.")
        request.event.set()

    @Slot(str, int)
    def update_progress(self, _transfer: str, value: int) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(value)

    @Slot()
    def finish_receive(self) -> None:
        if self.receiving:
            self.reset_workflow(reset_link=False)

    @Slot(bool)
    def finish_transfer(self, succeeded: bool) -> None:
        if succeeded:
            self.paths.clear()
            self.file_list.clear()
        self.reset_workflow()

    @Slot(object)
    def finish_transfer_result(self, result) -> None:
        if result.succeeded:
            self.finish_transfer(True)
            return
        if (getattr(result, "may_fallback", False) and self.selected_endpoint
                and self.selected_endpoint.get("route") == "lan"):
            match = next(((radio_id, peer) for radio_id, peer in self.radio_peers.items()
                          if peer.get("device_id") == self.selected_endpoint["device_id"]), None)
            if match:
                radio_id, peer = match
                self.pending_radio_id = radio_id
                self.selected_endpoint = dict(peer)
                self.send_started = False
                self.status.setText("Temporary hotspot unavailable; using Wi-Fi Direct fallback...")
                try:
                    self.radio.connect_wifi_direct(radio_id, self.attempt_id)
                    return
                except RuntimeError as exc:
                    self.status.setText(f"Wi-Fi Direct fallback failed: {exc}")
        self.finish_transfer(False)

    def reset_workflow(self, reset_link: bool = True) -> None:
        self.scan_timer.stop()
        self.scan_pending = False
        self.workflow_active = False
        self.pending_radio_id = None
        self.pending_peer = None
        self.receiving = False
        self.incoming_radio_id = None
        self.receive_offer_active = False
        self.attempt_id = None
        self.selected_endpoint = None
        self.send_started = False
        self.progress.setRange(0, 100)
        self.set_busy(False)
        if reset_link:
            self.network.clear_links()
        if reset_link and hasattr(self.radio, "reset_wifi_direct"):
            try:
                self.radio.reset_wifi_direct()
            except Exception as exc:
                logger.warning("Error resetting Wi-Fi Direct on radio: %s", exc)
        self.refresh_nearby_devices()
        QTimer.singleShot(2000, self.scan_timer.start)

    def closeEvent(self, event: QCloseEvent) -> None:
        self.scan_timer.stop()
        self.expiry_timer.stop()
        self.radio.close()
        self.discovery.close()
        self.network.close()
        self.store.close()
        event.accept()


def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    def report_uncaught(exception_type, exception, traceback):
        logger.critical("Uncaught application error", exc_info=(exception_type, exception, traceback))

    sys.excepthook = report_uncaught
    logger.info("Starting Local Secure Share with Python %s", sys.version.replace("\n", " "))
    app = QApplication(sys.argv)
    app.setApplicationName("Local Secure Share")
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    window = MainWindow()
    window.show()
    with loop:
        loop.run_forever()
