from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, QStandardPaths, Qt, QTimer, Signal, Slot
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
from .identity import load_or_create_identity, unb64
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
        self.ble_name_index: dict[str, str] = {}
        self.paths: list[Path] = []
        self.workflow_active = False
        self.pending_ble_token: str | None = None
        self.pending_radio_id: str | None = None
        self.pending_peer: DiscoveredPeer | None = None
        self.scan_pending = False

        self._build_ui()
        self._connect_signals()

        self.radio = NativeRadio(
            self.identity.device_id,
            self.network.port,
            self.bridge.radio_event.emit,
            public_key=self.identity.public_b64,
        )
        self.scan_timer = QTimer(self)
        self.scan_timer.setInterval(12000)
        self.scan_timer.timeout.connect(self.scan_radios)
        self.ble_expiry_timer = QTimer(self)
        self.ble_expiry_timer.setInterval(5000)
        self.ble_expiry_timer.timeout.connect(self.prune_nearby_devices)
        self.ble_expiry_timer.start()
        if self.radio.start():
            self.status.setText("Starting Bluetooth discovery…")
            self.scan_timer.start()
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
        self.status.setText("Connecting to the nearby device...")

        # Connect immediately if a matching Wi-Fi Direct peer was already discovered
        for radio_id, radio_peer in list(self.radio_peers.items()):
            self._connect_matching_wifi_peer(radio_id, radio_peer)
            if self.pending_radio_id:
                break

        if not self.pending_radio_id:
            # Start Wi-Fi Direct scanning to discover the endpoint without Bluetooth GATT pairing
            self.scan_timer.start()
            self.scan_radios()
            self.status.setText("Searching for direct Wi-Fi endpoint…")
            QTimer.singleShot(25000, lambda token=ble_token: self._wifi_lookup_timed_out(token))

    def _bluetooth_metadata_timed_out(self, token: str) -> None:
        if self.workflow_active and not self.pending_radio_id:
            self.status.setText("Searching for direct Wi-Fi endpoint…")
            QTimer.singleShot(15000, lambda t=token: self._wifi_lookup_timed_out(t))

    def _wifi_lookup_timed_out(self, token: str) -> None:
        if self.workflow_active and not self.pending_radio_id:
            self.status.setText(
                "Could not contact that device over Wi-Fi Direct. Keep both apps open and check that Wi-Fi is enabled."
            )
            self.reset_workflow()

    def _connect_matching_wifi_peer(self, radio_id: str, peer: dict) -> None:
        if not self.workflow_active:
            return
        if self.pending_radio_id:
            return

        target_token = self.pending_ble_token
        target_peer = self.ble_peers.get(target_token or "", {})
        target_name = str(target_peer.get("name") or "").strip().casefold()
        peer_name = str(peer.get("name") or "").strip().casefold()

        token_match = bool(target_token and peer.get("token") == target_token)
        name_match = bool(target_name and peer_name and target_name == peer_name)
        id_match = bool(target_peer.get("device_id") and target_peer.get("device_id") == peer.get("device_id"))

        if not (token_match or name_match or id_match):
            return

        public_key = peer.get("public_key") or target_peer.get("public_key") or ""
        peer = {
            **peer,
            "name": peer.get("name") or target_peer.get("name") or "Nearby device",
            "port": peer.get("port") or target_peer.get("port"),
            "public_key": public_key,
        }
        self.radio_peers[radio_id] = peer
        self.pending_radio_id = radio_id
        self.scan_timer.stop()
        self.status.setText(f"Creating a direct connection to {peer.get('name')}…")
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
        if self.workflow_active and self.pending_radio_id:
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
            "error", "fatal", "wifi_direct_error", "bluetooth_metadata_error",
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
            token = event["token"]
            name_key = str(event.get("name") or "").strip().casefold()
            existing_token = self.ble_name_index.get(name_key) if name_key else None
            if existing_token and existing_token != token:
                existing = self.ble_peers.get(existing_token, {})
                existing_score = (
                    bool(existing.get("is_paired")),
                    bool(existing.get("connectable", True)),
                    int(existing.get("rssi", -999)),
                )
                incoming_score = (
                    bool(event.get("is_paired")),
                    bool(event.get("connectable", True)),
                    int(event.get("rssi", -999)),
                )
                if (
                    existing_token == self.pending_ble_token
                    or existing_score >= incoming_score
                ):
                    return
                self.ble_tokens.discard(existing_token)
                self.ble_peers.pop(existing_token, None)
            if name_key:
                self.ble_name_index[name_key] = token
            self.ble_tokens.add(token)
            self.ble_peers[token] = event
            self.ble_status.setText(f"{len(self.ble_tokens)} nearby")
            self.refresh_nearby_devices()
        elif kind == "bluetooth_metadata_started":
            self.status.setText("Reading Wi-Fi connection details over Bluetooth...")
        elif kind == "wifi_direct_starting":
            self.status.setText("Bluetooth metadata received. Starting Wi-Fi Direct...")
        elif kind == "bluetooth_ready":
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
            name_key = str(event.get("name") or "").strip().casefold()
            if name_key:
                self.ble_name_index[name_key] = wifi_token
            self.status.setText(f"Found {event['name']} over Bluetooth. Finding its Wi-Fi Direct endpoint...")
            cached = next(
                ((radio_id, peer) for radio_id, peer in self.radio_peers.items()
                 if peer.get("token") == self.pending_ble_token),
                None,
            )
            if cached:
                self._connect_matching_wifi_peer(*cached)
            else:
                self.scan_timer.start()
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
            # Establish the transport silently. The signed file offer below is
            # the receiver's single user-facing Accept/Decline decision.
            self.scan_timer.stop()
            self.scan_pending = False
            event["accepted"] = True
            event["_decision"].set()
            self.status.setText("Nearby sender found. Preparing the secure file offer…")
        elif kind == "wifi_direct_connected":
            self.handle_wifi_connected(event)
        elif kind in error_events:
            self.scan_pending = False
            phase = event.get("phase")
            prefix = f"{phase}: " if phase and phase != "unknown" else ""
            self.status.setText(f"Radio error: {prefix}{event.get('message') or event.get('error') or kind}")
            if self.workflow_active and kind not in ("bluetooth_discovery_error", "bluetooth_metadata_error"):
                self.reset_workflow()
            elif kind == "bluetooth_metadata_error" and self.workflow_active and not self.pending_radio_id:
                logger.warning("Bluetooth metadata error: %s; continuing Wi-Fi Direct search", event.get("message"))
                self.status.setText("Searching for direct Wi-Fi endpoint…")

    def refresh_nearby_devices(self) -> None:
        selected = self.pending_ble_token
        self.devices.clear()
        wifi_by_token = {peer.get("token"): peer for peer in self.radio_peers.values()}
        for token in sorted(self.ble_tokens):
            peer = wifi_by_token.get(token, {})
            ble_peer = self.ble_peers.get(token, {})
            trusted = self.store.peer(peer.get("device_id", "")) if peer else None
            trust = " · trusted" if trusted else " · new device"
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

    def prune_nearby_devices(self) -> None:
        cutoff = time.monotonic() - 20.0
        removed = False
        for token, peer in list(self.ble_peers.items()):
            if token == self.pending_ble_token or float(peer.get("seen_at", 0.0)) >= cutoff:
                continue
            self.ble_peers.pop(token, None)
            self.ble_tokens.discard(token)
            name_key = str(peer.get("name") or "").strip().casefold()
            if name_key and self.ble_name_index.get(name_key) == token:
                self.ble_name_index.pop(name_key, None)
            removed = True
        if removed:
            self.ble_status.setText(f"{len(self.ble_tokens)} nearby")
            self.refresh_nearby_devices()

    def handle_wifi_connected(self, event: dict) -> None:
        logger.info(
            "handle_wifi_connected: workflow_active=%s pending_radio_id=%r event_id=%r local=%s remote=%s",
            self.workflow_active, self.pending_radio_id, event.get("id"),
            event.get("local_address"), event.get("remote_address"),
        )
        address = event.get("remote_address", "")
        if ":" in address:
            logger.info("Skipping IPv6 endpoint %s; waiting for IPv4", address)
            return  # The file listener is IPv4; wait for the IPv4 endpoint event.

        raw_event_id = str(event.get("id") or "").strip()
        event_id = raw_event_id.replace("_PendingRequest", "").replace("_pendingrequest", "").casefold()
        pending_id = str(self.pending_radio_id or "").strip().replace("_PendingRequest", "").replace("_pendingrequest", "").casefold()

        matching_peer_id = None
        for r_id in self.radio_peers:
            clean_r_id = r_id.replace("_PendingRequest", "").replace("_pendingrequest", "").casefold()
            if clean_r_id == event_id:
                matching_peer_id = r_id
                break

        if not self.workflow_active or (pending_id and event_id != pending_id):
            if self.paths and (matching_peer_id or self.radio_peers):
                target_radio_id = matching_peer_id or (list(self.radio_peers.keys())[0] if len(self.radio_peers) == 1 else None)
                if target_radio_id:
                    logger.info(
                        "Re-activating workflow for Wi-Fi Direct connection to %s (has pending files)",
                        event.get("name") or target_radio_id,
                    )
                    self.workflow_active = True
                    self.pending_radio_id = target_radio_id
                else:
                    logger.warning("Wi-Fi Direct connected with pending files but multiple ambiguous peers: %s", list(self.radio_peers.keys()))
                    return
            else:
                if not self.paths:
                    logger.info(
                        "Wi-Fi Direct connected to %s as receiver; waiting for sender file offer",
                        event.get("name") or event.get("id"),
                    )
                else:
                    logger.warning(
                        "Ignoring wifi_direct_connected: workflow_active=%s id_match=%s (pending=%r event=%r paths=%d)",
                        self.workflow_active, event_id == pending_id, self.pending_radio_id, event.get("id"), len(self.paths),
                    )
                return

        radio_peer = self.radio_peers.get(self.pending_radio_id or matching_peer_id or "", {})
        port = int(radio_peer.get("port") or 0)
        device_id = str(radio_peer.get("device_id") or radio_peer.get("name") or "nearby-device")
        public_key = str(radio_peer.get("public_key") or "")
        display_name = str(radio_peer.get("name") or "Nearby device")

        if not port or not public_key:
            target_name = str(event.get("name") or "").strip().casefold()
            for p in self.radio_peers.values():
                if str(p.get("name") or "").strip().casefold() == target_name:
                    port = int(p.get("port") or port)
                    device_id = str(p.get("device_id") or device_id)
                    public_key = str(p.get("public_key") or public_key)
                    display_name = str(p.get("name") or display_name)
                    if port and public_key:
                        break

        if not port:
            port = 22602

        self.pending_peer = DiscoveredPeer(
            f"radio:{self.pending_radio_id}", address, port, device_id, display_name
        )
        trusted = self.store.peer(device_id) if device_id else None
        if trusted and public_key and (trusted["blocked"] or trusted["public_key"] != public_key):
            self.status.setText("The nearby device identity changed. Forget it before connecting again.")
            self.reset_workflow()
            return
        if not trusted and public_key:
            try:
                if len(unb64(public_key)) == 32:
                    self.store.trust_peer(device_id, self.pending_peer.display_name, public_key)
            except Exception:
                pass
        self.status.setText("Sending the file offer; waiting for the receiver to accept…")
        logger.info("Initiating network file send to %s:%d (peer: %s)", address, port, device_id)
        self.network.send_files(self.pending_peer, list(self.paths))

    @Slot(object)
    def show_pair_code(self, request: Request) -> None:
        address, code = request.payload
        answer = QMessageBox.question(
            self,
            "Verify this device?",
            f"A nearby device at {address} wants to establish app trust.\n\n"
            f"Enter this one-time code on the sending device:\n\n{code}\n\n"
            "Allow this verification?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        request.result = answer == QMessageBox.Yes
        request.event.set()

    @Slot(object)
    def enter_pair_code(self, request: Request) -> None:
        name = request.payload
        value, ok = QInputDialog.getText(self, "Verify nearby device", f"Enter the code shown on {name}:")
        normalized = value.upper().replace("-", "").replace(" ", "")
        if ok and len(normalized) == 8 and all(char in CODE_ALPHABET for char in normalized):
            request.result = normalized
        elif ok:
            QMessageBox.warning(self, "Invalid code", "Enter the eight displayed letters or digits.")
        request.event.set()

    @Slot(object)
    def confirm_transfer(self, request: Request) -> None:
        peer, files = request.payload
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
        dialog.exec()
        if dialog.clickedButton() is accept_button:
            downloads = QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
            destination = Path(downloads) if downloads else Path.home() / "Downloads"
            destination.mkdir(parents=True, exist_ok=True)
            request.result = str(destination)
        request.event.set()

    @Slot()
    def finish_pairing_attempt(self) -> None:
        if not self.workflow_active or not self.pending_peer:
            return
        if self.store.peer(self.pending_peer.device_id):
            self.status.setText("Device verified. Sending the file offer; waiting for acceptance…")
            self.network.send_files(self.pending_peer, list(self.paths))
        else:
            self.status.setText("Device verification was not completed.")
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
        if hasattr(self.radio, "reset_wifi_direct"):
            try:
                self.radio.reset_wifi_direct()
            except Exception as exc:
                logger.warning("Error resetting Wi-Fi Direct on radio: %s", exc)
        self.refresh_nearby_devices()
        QTimer.singleShot(2000, self.scan_timer.start)

    def closeEvent(self, event: QCloseEvent) -> None:
        self.scan_timer.stop()
        self.ble_expiry_timer.stop()
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
