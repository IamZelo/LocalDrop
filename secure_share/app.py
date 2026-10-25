from __future__ import annotations

import asyncio
import logging
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
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

from .discovery import DiscoveredPeer, Discovery
from .identity import load_or_create_identity
from .native_radio import NativeRadio
from .network import InteractionCallbacks, NetworkManager
from .protocol import CODE_ALPHABET
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
    discovery_changed = Signal(object)
    pairing_display = Signal(object)
    pairing_input = Signal(object)
    transfer_offer = Signal(object)
    paired_changed = Signal()
    pairing_finished = Signal()
    transfer_finished = Signal(bool)
    radio_event = Signal(object)

    def _wait(self, signal: Signal, payload: object, timeout: int = 300):
        request = Request(payload)
        signal.emit(request)
        request.event.wait(timeout)
        return request.result

    def show_pairing_code(self, address: str, code: str) -> bool:
        return bool(self._wait(self.pairing_display, (address, code)))

    def request_pairing_code(self, name: str) -> str | None:
        result = self._wait(self.pairing_input, name)
        return str(result) if result else None

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
            self.bridge.show_pairing_code,
            self.bridge.request_pairing_code,
            self.bridge.accept_transfer,
            self.bridge.status_changed.emit,
            self.bridge.progress_changed.emit,
            self.bridge.paired_changed.emit,
            self.bridge.pairing_finished.emit,
            self.bridge.transfer_finished.emit,
        )
        self.network = NetworkManager(self.identity, self.store, callbacks)
        self.discovery = Discovery(
            self.identity.device_id,
            self.identity.display_name,
            self.network.port,
            self.bridge.discovery_changed.emit,
        )

        self.lan_peers: dict[str, DiscoveredPeer] = {}
        self.radio_peers: dict[str, dict] = {}
        self.ble_tokens: set[str] = set()
        self.ble_peers: dict[str, dict] = {}
        self.paths: list[Path] = []
        self.workflow_active = False
        self.pending_ble_token: str | None = None
        self.pending_radio_id: str | None = None
        self.pending_peer: DiscoveredPeer | None = None
        self.scan_pending = False

        self._build_ui()
        self._connect_signals()

        self.radio = NativeRadio(self.identity.device_id, self.network.port, self.bridge.radio_event.emit)
        self.scan_timer = QTimer(self)
        self.scan_timer.setInterval(4000)
        self.scan_timer.timeout.connect(self.scan_radios)
        if self.radio.start():
            self.status.setText("Starting Bluetooth discovery…")
        else:
            self.status.setText("Bluetooth radio unavailable. Run: python -m secure_share.diagnostics")

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(10)

        title = QLabel("Local Secure Share")
        title.setStyleSheet("font-size: 25px; font-weight: 650")
        root.addWidget(title)
        subtitle = QLabel(f"{self.identity.display_name} · Bluetooth discovery · Direct Wi-Fi transfer")
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
        self.ble_status = QLabel("Bluetooth starting…")
        self.ble_status.setStyleSheet("color: #666")
        device_header.addWidget(self.ble_status)
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
        self.bridge.progress_changed.connect(lambda _transfer, value: self.progress.setValue(value))
        self.bridge.discovery_changed.connect(self.update_lan_peers)
        self.bridge.pairing_display.connect(self.show_pair_code)
        self.bridge.pairing_input.connect(self.enter_pair_code)
        self.bridge.transfer_offer.connect(self.confirm_transfer)
        self.bridge.paired_changed.connect(self.refresh_nearby_devices)
        self.bridge.pairing_finished.connect(self.finish_pairing_attempt)
        self.bridge.transfer_finished.connect(self.finish_transfer)
        self.bridge.radio_event.connect(self.handle_radio_event)
        self.file_list.files_dropped.connect(self.add_paths)
        self.add_button.clicked.connect(self.pick_files)
        self.remove_button.clicked.connect(self.remove_files)
        self.devices.itemClicked.connect(self.device_clicked)

    @Slot(object)
    def update_lan_peers(self, peers: list[DiscoveredPeer]) -> None:
        self.lan_peers = {peer.device_id: peer for peer in peers}

    @Slot(object)
    def add_paths(self, paths: list[Path]) -> None:
        existing = {str(path.resolve()) for path in self.paths}
        for path in paths:
            if path.is_file() and str(path.resolve()) not in existing:
                self.paths.append(path)
                self.file_list.addItem(f"{path.name}  ({path.stat().st_size:,} bytes)")
                existing.add(str(path.resolve()))
        if self.paths:
            self.status.setText("Files ready. Click a nearby Bluetooth device to send.")

    def pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files")
        self.add_paths([Path(value) for value in files])

    def remove_files(self) -> None:
        rows = sorted((self.file_list.row(item) for item in self.file_list.selectedItems()), reverse=True)
        for row in rows:
            self.file_list.takeItem(row)
            self.paths.pop(row)

    @Slot(QListWidgetItem)
    def device_clicked(self, item: QListWidgetItem) -> None:
        ble_token = item.data(Qt.UserRole)
        if not ble_token:
            return
        if self.workflow_active:
            self.status.setText("A send request is already in progress.")
            return
        if not self.paths:
            QMessageBox.information(self, "Drop a file first", "Add or drop at least one file before selecting a device.")
            return
        if ble_token not in self.ble_tokens:
            self.status.setText("That Bluetooth device is no longer nearby.")
            self.refresh_nearby_devices()
            return

        self.workflow_active = True
        self.pending_ble_token = ble_token
        self.pending_radio_id = None
        self.pending_peer = None
        self.devices.setEnabled(False)
        self.progress.setValue(0)
        self.status.setText("Pairing with the device over Bluetooth…")

        # Establish the Bluetooth relationship and read the peer's encrypted
        # metadata before turning on Wi-Fi Direct discovery.
        try:
            peer = self.ble_peers[ble_token]
            self.radio.pair_bluetooth(peer["device_id"], peer["address"], peer["address_type"])
        except (KeyError, RuntimeError) as exc:
            self.status.setText(f"Bluetooth pairing could not start: {exc}")
            self.reset_workflow()
            return
        QTimer.singleShot(60000, lambda token=ble_token: self._bluetooth_pairing_timed_out(token))

    def _bluetooth_pairing_timed_out(self, token: str) -> None:
        if self.workflow_active and self.pending_ble_token == token:
            logger.error("Bluetooth pairing timed out after 60 seconds for discovery token %s", token)
            self.radio.cancel_bluetooth_pairing()
            self.status.setText("Bluetooth pairing or encrypted metadata exchange timed out. See the console diagnostics.")
            self.reset_workflow()

    def _wifi_lookup_timed_out(self, token: str) -> None:
        if self.workflow_active and self.pending_ble_token == token and not self.pending_radio_id:
            self.status.setText(
                "Could not contact that device over Wi-Fi Direct. Keep both apps open and check that Wi-Fi is enabled."
            )
            self.reset_workflow()

    def _connect_matching_wifi_peer(self, radio_id: str, peer: dict) -> None:
        if not self.workflow_active or peer.get("token") != self.pending_ble_token:
            return
        if self.pending_radio_id:
            return
        self.pending_radio_id = radio_id
        self.scan_timer.stop()
        self.status.setText(f"Waiting for {peer.get('name') or 'the nearby device'} to accept the connection…")
        try:
            self.radio.connect_wifi_direct(radio_id)
            QTimer.singleShot(45000, lambda target=radio_id: self._wifi_connection_timed_out(target))
        except RuntimeError as exc:
            self.status.setText(str(exc))
            self.reset_workflow()

    def _wifi_connection_timed_out(self, radio_id: str) -> None:
        if self.workflow_active and self.pending_radio_id == radio_id and self.pending_peer is None:
            self.status.setText("The receiving device did not complete the Wi-Fi Direct connection.")
            self.reset_workflow()

    def scan_radios(self) -> None:
        if self.scan_pending or not self.radio.supported:
            return
        self.scan_pending = True
        try:
            self.radio.scan_wifi_direct()
        except RuntimeError as exc:
            self.scan_pending = False
            self.status.setText(str(exc))

    @Slot(object)
    def handle_radio_event(self, event: dict) -> None:
        kind = event.get("event")
        error_events = {
            "error", "fatal", "wifi_direct_error", "bluetooth_pairing_error",
            "bluetooth_discovery_error", "bluetooth_stopped",
        }
        if kind in error_events:
            logger.error("Radio event: %s", {key: value for key, value in event.items() if key != "traceback"})
            if event.get("traceback"):
                logger.error("Full radio traceback:\n%s", event["traceback"])
        elif kind == "ble_peer":
            logger.debug("Radio event: %s", event)
        else:
            logger.info("Radio event: %s", event)

        if kind == "ready":
            implementation = event.get("implementation", "native")
            self.ble_status.setText(f"Scanning · {implementation}")
        elif kind == "ble_peer":
            self.ble_tokens.add(event["token"])
            self.ble_peers[event["token"]] = event
            self.ble_status.setText(f"{len(self.ble_tokens)} nearby")
            self.refresh_nearby_devices()
        elif kind == "bluetooth_pairing_started":
            self.status.setText("Waiting for Windows Bluetooth pairing to complete…")
        elif kind == "bluetooth_pairing_ceremony":
            self.status.setText("Confirm the Windows Bluetooth pairing prompt...")
        elif kind == "wifi_direct_starting":
            self.status.setText("Bluetooth paired. Starting Wi-Fi Direct...")
        elif kind == "bluetooth_paired":
            if not self.workflow_active or not self.pending_ble_token:
                return
            discovered = self.ble_peers.get(self.pending_ble_token, {})
            if event.get("address") != discovered.get("address"):
                return
            discovery_token = self.pending_ble_token
            wifi_token = event["token"]
            discovered.update(event)
            self.ble_peers.pop(discovery_token, None)
            self.ble_tokens.discard(discovery_token)
            self.ble_peers[wifi_token] = discovered
            self.ble_tokens.add(wifi_token)
            self.pending_ble_token = wifi_token
            self.status.setText(f"Bluetooth paired with {event['name']}. Finding its Wi-Fi Direct endpoint…")
            cached = next(
                ((radio_id, peer) for radio_id, peer in self.radio_peers.items()
                 if peer.get("token") == self.pending_ble_token),
                None,
            )
            if cached:
                self._connect_matching_wifi_peer(*cached)
            else:
                self.scan_radios()
            QTimer.singleShot(30000, lambda token=wifi_token: self._wifi_lookup_timed_out(token))
            self.refresh_nearby_devices()
        elif kind == "wifi_direct_peer":
            self.radio_peers[event["id"]] = event
            self._connect_matching_wifi_peer(event["id"], event)
            self.refresh_nearby_devices()
        elif kind == "wifi_direct_scan_complete":
            self.scan_pending = False
            if self.workflow_active and not self.pending_radio_id and not event.get("count"):
                self.status.setText("Bluetooth found. Waiting for its Wi-Fi Direct endpoint…")
            self.refresh_nearby_devices()
        elif kind == "wifi_direct_connection_request":
            answer = QMessageBox.question(
                self,
                "Incoming nearby connection",
                f"{event.get('name') or 'A nearby device'} wants to create a direct Wi-Fi connection.\n\nAccept?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            event["accepted"] = answer == QMessageBox.Yes
            event["_decision"].set()
            if event["accepted"]:
                self.status.setText("Connection accepted. Establishing the direct Wi-Fi link…")
        elif kind == "wifi_direct_connected":
            self.handle_wifi_connected(event)
        elif kind in error_events:
            self.scan_pending = False
            phase = event.get("phase")
            prefix = f"{phase}: " if phase and phase != "unknown" else ""
            self.status.setText(f"Radio error: {prefix}{event.get('message') or event.get('error') or kind}")
            if self.workflow_active and kind != "bluetooth_discovery_error":
                self.reset_workflow()

    def refresh_nearby_devices(self) -> None:
        selected = self.pending_ble_token
        self.devices.clear()
        wifi_by_token = {peer.get("token"): peer for peer in self.radio_peers.values()}
        for token in sorted(self.ble_tokens):
            peer = wifi_by_token.get(token, {})
            ble_peer = self.ble_peers.get(token, {})
            trusted = self.store.peer(peer.get("device_id", "")) if peer else None
            trust = " · trusted" if trusted else " · first-time pairing required"
            name = peer.get("name") or ble_peer.get("name") or f"Nearby device {token[-4:]}"
            item = QListWidgetItem(f"{name}\nBluetooth nearby{trust}")
            item.setData(Qt.UserRole, token)
            self.devices.addItem(item)
            if token == selected:
                self.devices.setCurrentItem(item)
        if not self.ble_tokens:
            item = QListWidgetItem("Searching for nearby devices over Bluetooth…")
            item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            self.devices.addItem(item)

    def handle_wifi_connected(self, event: dict) -> None:
        if not self.workflow_active or event.get("id") != self.pending_radio_id:
            return
        address = event.get("remote_address", "")
        if ":" in address:
            return  # The file listener is IPv4; wait for the IPv4 endpoint event.
        radio_peer = self.radio_peers.get(self.pending_radio_id or "", {})
        try:
            port = int(radio_peer["port"])
            device_id = str(radio_peer["device_id"])
        except (KeyError, TypeError, ValueError):
            self.status.setText("The nearby device uses an older discovery format. Update and restart both apps.")
            self.reset_workflow()
            return
        self.pending_peer = DiscoveredPeer(
            f"radio:{self.pending_radio_id}", address, port, device_id, radio_peer.get("name") or "Nearby device"
        )
        if self.store.peer(device_id):
            self.status.setText("Sending a file offer; waiting for the receiver to accept…")
            self.network.send_files(self.pending_peer, list(self.paths))
        else:
            self.status.setText("First connection: secure device pairing is required before the file offer.")
            if not self.network.pair(self.pending_peer):
                self.reset_workflow()

    @Slot(object)
    def show_pair_code(self, request: Request) -> None:
        address, code = request.payload
        answer = QMessageBox.question(
            self,
            "Allow this device?",
            f"A nearby device at {address} wants to pair.\n\n"
            f"Enter this one-time code on the sending device:\n\n{code}\n\n"
            "Allow pairing?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        request.result = answer == QMessageBox.Yes
        request.event.set()

    @Slot(object)
    def enter_pair_code(self, request: Request) -> None:
        name = request.payload
        value, ok = QInputDialog.getText(self, "Enter pairing code", f"Enter the code shown on {name}:")
        normalized = value.upper().replace("-", "").replace(" ", "")
        if ok and len(normalized) == 8 and all(char in CODE_ALPHABET for char in normalized):
            request.result = normalized
        elif ok:
            QMessageBox.warning(self, "Invalid code", "Enter the eight displayed letters or digits.")
        request.event.set()

    @Slot(object)
    def confirm_transfer(self, request: Request) -> None:
        peer, files = request.payload
        descriptions = "\n".join(f"• {item['name']} ({item['size']:,} bytes)" for item in files)
        answer = QMessageBox.question(
            self,
            "Incoming file request",
            f"From verified device: {peer['name']}\n\n{descriptions}\n\nAccept and choose where to save?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            request.result = QFileDialog.getExistingDirectory(self, "Choose destination folder") or None
        request.event.set()

    @Slot()
    def finish_pairing_attempt(self) -> None:
        if not self.workflow_active or not self.pending_peer:
            return
        if self.store.peer(self.pending_peer.device_id):
            self.status.setText("Paired. Sending the file offer; waiting for acceptance…")
            self.network.send_files(self.pending_peer, list(self.paths))
        else:
            self.status.setText("Pairing was not completed.")
            self.reset_workflow()

    @Slot(bool)
    def finish_transfer(self, succeeded: bool) -> None:
        if succeeded:
            self.paths.clear()
            self.file_list.clear()
        self.reset_workflow()

    def reset_workflow(self) -> None:
        self.scan_timer.stop()
        self.scan_pending = False
        self.workflow_active = False
        self.pending_ble_token = None
        self.pending_radio_id = None
        self.pending_peer = None
        self.devices.setEnabled(True)
        self.refresh_nearby_devices()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.scan_timer.stop()
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
