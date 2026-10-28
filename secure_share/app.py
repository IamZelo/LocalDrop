from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, QSize, QStandardPaths, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QColor, QCloseEvent, QDragEnterEvent, QDropEvent, QIcon, QPalette, QTransform
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
    QMenu,
    QCheckBox,
    QProgressBar,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)
from qasync import QEventLoop
from qt_material_icons import MaterialIcon

from .discovery import DiscoveredPeer
try:  # lightweight test boundaries may expose only the peer record
    from .discovery import Discovery
except ImportError:  # pragma: no cover - used by isolated UI tests
    Discovery = None  # type: ignore[misc,assignment]
from .connectivity import Transport
from .identity import load_or_create_identity, unb64, update_display_name
if sys.platform == "win32":
    from .native_radio import NativeRadio
from .network import InteractionCallbacks, NetworkManager, TransferApproval
from .storage import LocalStore

logger = logging.getLogger("secure_share.app")
DEVICE_DATA_ROLE = Qt.UserRole
DEVICE_TRUSTED_ROLE = Qt.UserRole + 1
DEVICE_ONLINE_ROLE = Qt.UserRole + 2
DEVICE_ID_ROLE = Qt.UserRole + 3


@dataclass
class Request:
    payload: object
    event: threading.Event = field(default_factory=threading.Event)
    result: object = None


class UiBridge(QObject):
    status_changed = Signal(str)
    progress_changed = Signal(object)
    transfer_offer = Signal(object)
    transfer_finished = Signal(bool)
    transfer_result = Signal(object)
    receive_finished = Signal(object)
    receive_started = Signal()
    radio_event = Signal(object)
    discovery_changed = Signal(object)
    transport_changed = Signal(object)
    trust_changed = Signal()
    radio_loaded = Signal(object)

    def _wait(self, signal: Signal, payload: object, timeout: int = 300):
        request = Request(payload)
        signal.emit(request)
        if not request.event.wait(timeout):
            request.event.set()
            return None
        return request.result



    def accept_transfer(self, peer: dict, files: list[dict]) -> TransferApproval | None:
        result = self._wait(self.transfer_offer, (peer, files))
        return result if isinstance(result, TransferApproval) else None


class DropList(QListWidget):
    files_dropped = Signal(object)
    select_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setSelectionMode(QListWidget.ExtendedSelection)
        self.setMinimumHeight(150)
        self.setStyleSheet(
            "QListWidget { border: 2px dashed #8a8f98; border-radius: 10px; padding: 12px; }"
            "QListWidget:focus { border-color: #3478f6; }"
        )
        self.placeholder = QLabel("Select your files", self.viewport())
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.placeholder.setStyleSheet(
            "color: rgba(128, 128, 128, 150); background: transparent; "
            "font-size: 18px; font-weight: 600;"
        )
        self.sync_empty_state()

    def sync_empty_state(self) -> None:
        self.placeholder.setVisible(self.count() == 0)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self.placeholder.setGeometry(self.viewport().rect())

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.select_requested.emit()
            event.accept()
            return
        super().mousePressEvent(event)

    def clear(self) -> None:
        super().clear()
        self.sync_empty_state()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls() and any(url.isLocalFile() for url in event.mimeData().urls()):
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:
        event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        paths = [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]
        self.files_dropped.emit([path for path in paths if path.is_file()])
        event.acceptProposedAction()


def _readable_size(size: int | float) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size:,.0f} B"


def _readable_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "Estimating…"
    rounded = int(seconds + 0.5)
    if rounded < 60:
        return f"{rounded}s remaining"
    minutes, remainder = divmod(rounded, 60)
    if minutes < 60:
        return f"{minutes}m {remainder:02d}s remaining"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m remaining"


def _readable_elapsed(seconds: float) -> str:
    rounded = max(0, int(seconds + 0.5))
    if rounded < 60:
        unit = "second" if rounded == 1 else "seconds"
        return f"{rounded} {unit}"
    minutes, remainder = divmod(rounded, 60)
    if minutes < 60:
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit} {remainder:02d} seconds"
    hours, minutes = divmod(minutes, 60)
    hour_unit = "hour" if hours == 1 else "hours"
    minute_unit = "minute" if minutes == 1 else "minutes"
    return f"{hours} {hour_unit} {minutes:02d} {minute_unit}"


class DeviceRow(QWidget):
    """Friendly two-column device row with transport detail and a status badge."""

    def __init__(self, name: str, detail: str, status: str, *, muted: bool = False):
        super().__init__()
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 9)
        text = QVBoxLayout()
        text.setSpacing(2)
        name_label = QLabel(name)
        muted_color = "#5f6368"
        secondary_color = self.palette().color(QPalette.PlaceholderText).name()
        if muted:
            name_label.setStyleSheet(
                f"font-size: 13px; font-weight: 650; color: {muted_color};"
            )
        else:
            name_label.setStyleSheet("font-size: 13px; font-weight: 650;")
        detail_label = QLabel(detail)
        detail_label.setStyleSheet(
            f"font-size: 11px; color: {muted_color if muted else secondary_color};"
        )
        text.addWidget(name_label)
        text.addWidget(detail_label)
        layout.addLayout(text)
        layout.addStretch()
        badge = QLabel(status)
        dark_theme = self.palette().color(QPalette.Base).lightness() < 128
        if status == "Online":
            foreground = "#86efac" if dark_theme else "#15803d"
            badge.setStyleSheet(
                f"color: {foreground}; background: transparent; "
                "font-size: 11px; font-weight: 650;"
            )
        else:
            badge.setStyleSheet(
                f"color: {muted_color}; background: transparent; "
                "font-size: 11px; font-weight: 650;"
            )
        layout.addWidget(badge)


class FileRow(QWidget):
    remove_requested = Signal(str)

    def __init__(self, path: Path):
        super().__init__()
        self.path_key = str(path.resolve())
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 4, 4)
        label = QLabel(f"{path.name}  ·  {_readable_size(path.stat().st_size)}")
        label.setToolTip(str(path))
        layout.addWidget(label, 1)
        remove = QToolButton()
        remove_icon = MaterialIcon("delete")
        remove_icon.set_color(self.palette().color(QPalette.ButtonText))
        remove.setIcon(remove_icon)
        remove.setIconSize(QSize(16, 16))
        remove.setAutoRaise(True)
        remove.setToolTip(f"Remove {path.name} from this transfer")
        remove.setAccessibleName(f"Remove {path.name}")
        remove.clicked.connect(lambda: self.remove_requested.emit(self.path_key))
        layout.addWidget(remove)


class DeviceSectionHeader(QWidget):
    def __init__(self, title: str):
        super().__init__()
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 4)
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 12px; font-weight: 700;")
        layout.addWidget(title_label)

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
            route_started=self.bridge.transport_changed.emit,
            trust_changed=self.bridge.trust_changed.emit,
            receive_started=self.bridge.receive_started.emit,
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
        self.send_started_at: float | None = None
        self.paths: list[Path] = []
        self.workflow_active = False
        self.pending_radio_id: str | None = None
        self.pending_peer: DiscoveredPeer | None = None
        self.scan_pending = False
        self.discovery: Discovery | None = None
        self._closing = False
        self.refresh_animation_index = 0
        self.refresh_in_progress = False
        self.refresh_animation_timer = QTimer(self)
        self.refresh_animation_timer.setInterval(120)

        self._build_ui()
        self._connect_signals()

        # Zeroconf registration probes the network and must not delay the first paint.
        threading.Thread(target=self._start_discovery, daemon=True,
                         name="lan-discovery-start").start()

        self.radio = None
        self.scan_timer = None
        if sys.platform == "win32":
            self.scan_timer = QTimer(self)
            self.scan_timer.setInterval(12000)
            self.scan_timer.timeout.connect(self.scan_radios)
        self.expiry_timer = QTimer(self)
        self.expiry_timer.setInterval(5000)
        self.expiry_timer.timeout.connect(self.prune_nearby_devices)
        self.expiry_timer.start()
        if sys.platform == "win32":
            threading.Thread(target=self._load_radio, daemon=True,
                             name="wifi-direct-load").start()

    def _start_discovery(self) -> None:
        try:
            discovery = Discovery(
                self.identity.device_id, self.identity.display_name,
                self.network.port, self.identity.public_b64,
                self._emit_discovery_change,
                frozenset({"lan", "wifi_direct"}) if sys.platform == "win32"
                else frozenset({"lan"}),
            )
            if self._closing:
                discovery.close()
            else:
                self.discovery = discovery
        except Exception as exc:
            logger.exception("LAN discovery failed to start")
            if not self._closing:
                self.bridge.status_changed.emit(f"LAN discovery unavailable: {exc}")

    def _emit_discovery_change(self, peers: list[DiscoveredPeer]) -> None:
        if not self._closing:
            self.bridge.discovery_changed.emit(peers)

    def _load_radio(self) -> None:
        radio = NativeRadio(self.identity.device_id, self.network.port,
                            self.bridge.radio_event.emit, public_key=self.identity.public_b64,
                            display_name=self.identity.display_name)
        if self._closing:
            radio.close()
        else:
            self.bridge.radio_loaded.emit(radio)

    @Slot(object)
    def _finish_radio_load(self, radio) -> None:
        if self._closing:
            radio.close()
            return
        self.radio = radio
        if radio.start():
            self.status.setText("Starting Wi-Fi Direct...")
            self.scan_timer.start()
        else:
            self.status.setText("Wi-Fi Direct unavailable. Run: python -m secure_share.diagnostics")

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(10)

        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(2)
        title = QLabel("Local Secure Share")
        title.setStyleSheet("font-size: 25px; font-weight: 700")
        heading.addWidget(title)
        profile_row = QHBoxLayout()
        profile_row.setSpacing(4)
        self.profile_name = QLabel(self.identity.display_name)
        self.profile_name.setStyleSheet("color: #6b7280; font-size: 12px;")
        profile_row.addWidget(self.profile_name)
        self.edit_profile_button = QToolButton()
        edit_icon = MaterialIcon("edit")
        edit_icon.set_color(self.palette().color(QPalette.ButtonText))
        self.edit_profile_button.setIcon(edit_icon)
        self.edit_profile_button.setIconSize(QSize(16, 16))
        self.edit_profile_button.setAutoRaise(True)
        self.edit_profile_button.setToolTip("Edit this device's name")
        self.edit_profile_button.setAccessibleName("Edit this device's name")
        self.edit_profile_button.setFixedSize(22, 22)
        profile_row.addWidget(self.edit_profile_button)
        profile_row.addStretch()
        heading.addLayout(profile_row)
        header.addLayout(heading)
        header.addStretch()
        self.receive_status = QLabel()
        self.receive_status.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        header.addWidget(self.receive_status)
        root.addLayout(header)
        self.update_receive_status("ready")

        self.file_list = DropList()
        self.file_list.setToolTip("Drop regular files here; folders are not transferred")
        root.addWidget(self.file_list)
        device_header = QHBoxLayout()
        self.device_instruction = QLabel("Select device")
        device_header.addWidget(self.device_instruction)
        device_header.addStretch()
        self.radio_status = QLabel("Wi-Fi Direct starting..." if sys.platform == "win32" else "")
        self.radio_status.setStyleSheet("color: #666")
        if sys.platform == "win32":
            device_header.addWidget(self.radio_status)
        self.refresh_button = QToolButton()
        self.refresh_base_icon = MaterialIcon("refresh")
        self.refresh_base_icon.set_color(self.palette().color(QPalette.ButtonText))
        self.refresh_button.setIcon(self.refresh_base_icon)
        self.refresh_button.setIconSize(QSize(18, 18))
        self.refresh_button.setFixedSize(30, 30)
        self.refresh_button.setToolTip("Refresh nearby devices")
        self.refresh_button.setAccessibleName("Refresh nearby devices")
        device_header.addWidget(self.refresh_button)
        root.addLayout(device_header)

        self.devices = QListWidget()
        self.devices.setMinimumHeight(260)
        self._apply_device_list_theme()
        self.devices.setContextMenuPolicy(Qt.CustomContextMenu)
        root.addWidget(self.devices)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        progress_row = QHBoxLayout()
        progress_row.addWidget(self.progress, 1)
        self.transport_badge = QLabel()
        self.transport_badge.hide()
        progress_row.addWidget(self.transport_badge)
        self.cancel_button = QPushButton("Cancel transfer")
        self.cancel_button.hide()
        progress_row.addWidget(self.cancel_button)
        root.addLayout(progress_row)

        self.receive_details = QWidget()
        details_layout = QVBoxLayout(self.receive_details)
        details_layout.setContentsMargins(12, 8, 12, 8)
        details_layout.setSpacing(3)
        self.receive_file_label = QLabel()
        self.receive_file_label.setStyleSheet("font-weight: 650;")
        self.receive_summary_label = QLabel()
        self.receive_summary_label.setStyleSheet("color: #6b7280; font-size: 11px;")
        self.receive_rate_label = QLabel()
        self.receive_rate_label.setStyleSheet("color: #6b7280; font-size: 11px;")
        details_layout.addWidget(self.receive_file_label)
        details_layout.addWidget(self.receive_summary_label)
        details_layout.addWidget(self.receive_rate_label)
        self.receive_details.setStyleSheet(
            "QWidget { border: 1px solid rgba(128, 128, 128, 70); "
            "border-radius: 8px; background: rgba(128, 128, 128, 18); }"
            "QLabel { border: none; background: transparent; }"
        )
        self.receive_details.hide()
        root.addWidget(self.receive_details)
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
        self.bridge.receive_started.connect(self.begin_receive)
        self.bridge.radio_event.connect(self.handle_radio_event)
        self.bridge.discovery_changed.connect(self.handle_discovery)
        self.bridge.transport_changed.connect(self.set_transfer_transport)
        self.bridge.trust_changed.connect(self.refresh_nearby_devices)
        self.bridge.radio_loaded.connect(self._finish_radio_load)
        self.file_list.files_dropped.connect(self.add_paths)
        self.file_list.select_requested.connect(self.pick_files)
        self.edit_profile_button.clicked.connect(self.edit_profile)
        self.refresh_button.clicked.connect(self.refresh_devices)
        self.refresh_animation_timer.timeout.connect(self.advance_refresh_animation)
        self.cancel_button.clicked.connect(self.cancel_transfer)
        self.devices.customContextMenuRequested.connect(self.show_device_menu)
        self.devices.itemClicked.connect(self.device_clicked)

    def _apply_device_list_theme(self) -> None:
        palette = self.palette()
        border = palette.color(QPalette.Mid).name()
        selected = palette.color(QPalette.Highlight).name()
        selected_text = palette.color(QPalette.HighlightedText).name()
        
        # Grab the base window background color
        base_color = palette.color(QPalette.Base)
        
        # Check if the theme is Light or Dark based on text luminance
        is_dark_mode = palette.color(QPalette.Text).value() > 128
        
        # Generate a high-contrast hover color relative to the background
        if is_dark_mode:
            hover = base_color.lighter(130).name()
        else:
            hover = base_color.darker(110).name()
            
        self.devices.setStyleSheet(
            f"QListWidget {{ border: 1px solid {border}; border-radius: 9px; padding: 5px; }}"
            "QListWidget::item { border-radius: 7px; margin: 2px; }"
            f"QListWidget::item:hover {{ background: {hover}; }}"
            f"QListWidget::item:selected {{ background: {selected}; color: {selected_text}; }}"
            f"QListWidget::item:selected:!active {{ background: {selected}; color: {selected_text}; }}"
        )

    @Slot(object)
    def set_transfer_transport(self, transport) -> None:
        if transport is None:
            self.transport_badge.clear()
            self.transport_badge.hide()
            return
        value = getattr(transport, "value", str(transport))
        wifi_direct = value == Transport.WIFI_DIRECT.value
        label = "Wi-Fi Direct" if wifi_direct else "LAN"
        dark_theme = self.palette().color(QPalette.Base).lightness() < 128
        if wifi_direct:
            foreground, background = (("#e9d5ff", "#581c87") if dark_theme
                                      else ("#6b21a8", "#f3e8ff"))
        else:
            foreground, background = (("#bfdbfe", "#1e3a8a") if dark_theme
                                      else ("#1e40af", "#dbeafe"))
        self.transport_badge.setText(label)
        self.transport_badge.setStyleSheet(
            f"color: {foreground}; background: {background}; border-radius: 9px; "
            "padding: 4px 10px; font-size: 11px; font-weight: 700;"
        )
        self.transport_badge.show()

    @Slot(object)
    def add_paths(self, paths: list[Path]) -> None:
        if self.workflow_active or self.receiving:
            return
        existing = {str(path.resolve()) for path in self.paths}
        for path in paths:
            if path.is_file() and str(path.resolve()) not in existing:
                self.paths.append(path)
                item = QListWidgetItem()
                item.setData(Qt.UserRole, str(path.resolve()))
                row = FileRow(path)
                row.remove_requested.connect(self.remove_path)
                item.setSizeHint(row.sizeHint())
                self.file_list.addItem(item)
                self.file_list.setItemWidget(item, row)
                existing.add(str(path.resolve()))
        self.file_list.sync_empty_state()
        if self.paths:
            self.status.setText("Files ready. Click a nearby device to send.")
        self.refresh_nearby_devices()

    def pick_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files")
        self.add_paths([Path(value) for value in files])

    @Slot()
    def edit_profile(self) -> None:
        if self.workflow_active or self.receiving:
            return
        name, accepted = QInputDialog.getText(
            self, "Edit your profile", "Device name:", text=self.identity.display_name
        )
        if not accepted:
            return
        try:
            identity = update_display_name(self.identity, name)
        except (OSError, ValueError) as exc:
            self.status.setText(str(exc))
            return
        self.identity = identity
        self.network.identity = identity
        self.profile_name.setText(identity.display_name)
        if self.discovery:
            try:
                self.discovery.update_display_name(identity.display_name)
            except Exception as exc:
                logger.exception("Could not update LAN profile advertisement")
                self.status.setText(f"Name saved, but LAN advertisement could not update: {exc}")
                return
        if self.radio and hasattr(self.radio, "update_display_name"):
            try:
                self.radio.update_display_name(identity.display_name)
            except Exception as exc:
                logger.exception("Could not update Wi-Fi Direct profile advertisement")
                self.status.setText(f"Name saved, but Wi-Fi Direct advertisement could not update: {exc}")
                return
        self.status.setText("Your device name has been updated.")

    @Slot(str)
    def remove_path(self, path_key: str) -> None:
        if self.workflow_active or self.receiving:
            return
        row = next((index for index in range(self.file_list.count())
                    if self.file_list.item(index).data(Qt.UserRole) == path_key), -1)
        if row < 0:
            return
        self.file_list.takeItem(row)
        self.paths.pop(row)
        self.file_list.sync_empty_state()
        self.refresh_nearby_devices()

    def show_device_menu(self, position) -> None:
        item = self.devices.itemAt(position)
        if not item or not item.data(DEVICE_TRUSTED_ROLE):
            return
        menu = QMenu(self)
        rename = menu.addAction("Rename device")
        revoke = menu.addAction("Revoke trust")
        selected = menu.exec(self.devices.mapToGlobal(position))
        if selected not in (rename, revoke):
            return
        device_id = item.data(DEVICE_ID_ROLE)
        if not device_id:
            return
        if selected is rename:
            peer = self.store.peer(str(device_id))
            if not peer:
                return
            alias, accepted = QInputDialog.getText(
                self, "Rename trusted device", "Device name:", text=peer["name"]
            )
            if not accepted:
                return
            if len(alias.strip()) > 80:
                self.status.setText("Device names must be 80 characters or fewer.")
                return
            self.store.rename_peer(str(device_id), alias)
            self.status.setText("Trusted device name updated.")
            self.refresh_nearby_devices()
            return
        answer = QMessageBox.question(
            self, "Revoke trust",
            "Revoke trust for this device? Future transfers will require approval and establish trust again.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        self.store.revoke_trust(str(device_id))
        self.status.setText("Device trust revoked. Transfer history was kept.")
        self.refresh_nearby_devices()

    def refresh_devices(self) -> None:
        if self.workflow_active or self.receiving:
            return
        self.start_refresh_animation()
        self.status.setText("Refreshing nearby devices...")
        if self.discovery:
            self.discovery.refresh()
        self.refresh_nearby_devices()
        if self.radio and self.radio_ready and not self.scan_pending:
            self.scan_radios()
        else:
            QTimer.singleShot(800, self.finish_refresh_animation)

    def start_refresh_animation(self) -> None:
        if self.refresh_in_progress:
            return
        self.refresh_in_progress = True
        self.refresh_animation_index = 0
        self.refresh_button.setEnabled(False)
        self.advance_refresh_animation()
        self.refresh_animation_timer.start()
        QTimer.singleShot(30000, self.finish_refresh_animation)

    @Slot()
    def advance_refresh_animation(self) -> None:
        self.refresh_animation_index = (self.refresh_animation_index + 1) % 12
        pixmap = self.refresh_base_icon.pixmap(18, 18)
        transform = QTransform().rotate(self.refresh_animation_index * 30)
        self.refresh_button.setIcon(QIcon(pixmap.transformed(transform, Qt.SmoothTransformation)))

    @Slot()
    def finish_refresh_animation(self) -> None:
        if not self.refresh_in_progress:
            return
        self.refresh_in_progress = False
        self.refresh_animation_timer.stop()
        self.refresh_button.setIcon(self.refresh_base_icon)
        self.refresh_button.setEnabled(not self.workflow_active and not self.receiving)
        if not self.workflow_active and not self.receiving:
            self.status.setText("Nearby device list refreshed.")

    def set_busy(self, busy: bool) -> None:
        self.devices.setEnabled(not busy)
        self.file_list.setEnabled(not busy)
        self.edit_profile_button.setEnabled(not busy)
        self.refresh_button.setEnabled(not busy and not self.refresh_in_progress)
        self.cancel_button.setVisible(busy)
        self.cancel_button.setEnabled(busy)
        self.update_receive_status("busy" if busy else "ready")

    @Slot()
    def cancel_transfer(self) -> None:
        if not self.workflow_active and not self.receiving:
            return
        self.cancel_button.setEnabled(False)
        self.status.setText("Canceling transfer…")
        network_active = self.network.cancel_active_transfer()
        if not network_active:
            self.reset_workflow()

    def update_receive_status(self, state: str) -> None:
        if state == "ready":
            color, text = "#22c55e", "Ready to receive"
            tooltip = "This device is online and ready to accept an incoming file offer."
        elif state == "busy":
            color, text = "#f59e0b", "Transfer in progress"
            tooltip = "This device is busy and cannot start another transfer right now."
        else:
            color, text = "#9ca3af", "Receive unavailable"
            tooltip = "This device is not currently available for incoming transfers."
        self.receive_status.setText(f"●  {text}")
        self.receive_status.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: 650; padding: 6px 0;"
        )
        self.receive_status.setToolTip(tooltip)

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
            self.send_started_at = time.monotonic()
            self.workflow_active, self.send_started = True, True
            self.set_transfer_transport(Transport.LAN)
            self.attempt_id = uuid.uuid4().hex
            observed = self.discovery.routes_for(peer.device_id) if self.discovery else [peer]
            by_endpoint = {f"{route.host}:{route.port}": route
                           for route in [peer, *(item for item in observed if item.host != peer.host)]}
            ranked = self.store.rank_endpoints(peer.device_id, list(by_endpoint))
            routes = [by_endpoint[endpoint] for endpoint in ranked]
            self.selected_endpoint = {"device_id": peer.device_id, "name": peer.display_name,
                                      "public_key": peer.public_key, "route": "lan",
                                      "supports_wifi_direct": peer.supports_wifi_direct,
                                      "lan_routes": routes, "lan_route_index": 0}
            self.set_busy(True)
            self.progress.setRange(0, 0)
            self.status.setText(f"Same network: connecting to {peer.display_name}...")
            self._send_lan_route(peer)
            return
        peer = self.radio_peers.get(radio_id)
        if not peer:
            self.status.setText("Device no longer available. Waiting for a fresh scan.")
            return
        self.send_started_at = time.monotonic()
        self.attempt_id = uuid.uuid4().hex
        self.set_transfer_transport(Transport.WIFI_DIRECT)
        self.selected_endpoint = dict(peer)
        self.pending_radio_id = radio_id
        self.pending_peer = None
        self.send_started = False
        self.workflow_active = True
        self.set_busy(True)
        self.progress.setRange(0, 0)
        if self.scan_timer:
            self.scan_timer.stop()
        self.status.setText(f"Connecting to {peer['name']} over Wi-Fi Direct...")
        try:
            self.radio.connect_wifi_direct(radio_id, self.attempt_id)
        except RuntimeError as exc:
            self.status.setText(f"Connection failed: {exc}")
            self.reset_workflow()

    def _send_lan_route(self, peer: DiscoveredPeer) -> None:
        self.network.send_files(peer, list(self.paths), expected_public_key=peer.public_key,
                                local_address=peer.local_interface)

    def scan_radios(self) -> None:
        if not self.radio or not self.radio_ready or self.scan_pending or self.workflow_active or self.receiving:
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
            self.finish_refresh_animation()
        elif kind == "wifi_direct_scan_error":
            self.scan_pending = False
            self.radio_status.setText("Scan failed; retrying")
            self.finish_refresh_animation()
            if not self.workflow_active and not self.receiving:
                self.status.setText(f"Discovery failed: {event.get('message')}. Retrying automatically.")
        elif kind == "wifi_direct_connection_request":
            event["accepted"] = not self.workflow_active and not self.receiving
            if event["accepted"]:
                self.receiving = True
                self.incoming_radio_id = event.get("id")
                if self.scan_timer:
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
        files_ready = bool(self.paths)
        self.device_instruction.setText("Select device")
        self.device_instruction.setStyleSheet(
            "font-weight: 650; color: #2563eb" if files_ready else "color: #666"
        )
        trusted_by_id = {peer["device_id"]: peer for peer in self.store.peers()}
        online: dict[str, dict] = {}
        lan_ids = set()
        for device_id, peer in getattr(self, "lan_peers", {}).items():
            online[device_id] = {
                "device_id": device_id, "name": peer.display_name,
                "detail": "Same network (LAN)", "target": f"lan:{device_id}",
            }
            lan_ids.add(device_id)
        for radio_id, peer in sorted(self.radio_peers.items(), key=lambda entry: entry[1].get("name", "")):
            if peer.get("device_id") in lan_ids:
                continue
            device_id = peer.get("device_id")
            if device_id:
                online[device_id] = {
                    "device_id": device_id, "name": peer.get("name") or "Nearby computer",
                    "detail": "Nearby connection (Wi-Fi Direct)", "target": radio_id,
                }

        trusted_rows = []
        new_rows = []
        for device_id, peer in online.items():
            trusted = trusted_by_id.get(device_id)
            preferred_name = (trusted.get("alias") if trusted else None) or peer["name"]
            row = {**peer, "name": preferred_name,
                   "online": True, "trusted": trusted is not None}
            (trusted_rows if row["trusted"] else new_rows).append(row)
        for device_id, peer in trusted_by_id.items():
            if device_id not in online:
                trusted_rows.append({
                    "device_id": device_id, "name": peer["name"], "detail": "Last seen previously",
                    "target": None, "online": False, "trusted": True,
                })

        self._add_device_section("Trusted Devices")
        if trusted_rows:
            for row in sorted(trusted_rows, key=lambda value: (not value["online"], value["name"].casefold())):
                self._add_device_row(row, files_ready)
        else:
            self._add_empty_device_row("No trusted devices yet")

        self._add_device_section("New Devices")
        if new_rows:
            for row in sorted(new_rows, key=lambda value: value["name"].casefold()):
                self._add_device_row(row, files_ready)
        else:
            self._add_empty_device_row("No new devices online")

    def _add_device_section(self, title: str) -> None:
        item = QListWidgetItem()
        item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
        widget = DeviceSectionHeader(title)
        item.setSizeHint(widget.sizeHint())
        self.devices.addItem(item)
        self.devices.setItemWidget(item, widget)

    def _add_empty_device_row(self, message: str) -> None:
        item = QListWidgetItem(message)
        item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
        item.setForeground(QColor("#9ca3af"))
        self.devices.addItem(item)

    def _add_device_row(self, row: dict, files_ready: bool) -> None:
        online = bool(row["online"])
        item = QListWidgetItem()
        item.setData(DEVICE_DATA_ROLE, row["target"])
        item.setData(DEVICE_TRUSTED_ROLE, row["trusted"])
        item.setData(DEVICE_ONLINE_ROLE, online)
        item.setData(DEVICE_ID_ROLE, row["device_id"])
        if not online:
            item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            item.setToolTip("This trusted device is currently offline")
        elif not files_ready:
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            item.setToolTip("Add one or more files before selecting a device")
        widget = DeviceRow(row["name"], row["detail"], "Online" if online else "Offline",
                           muted=not online)
        item.setSizeHint(widget.sizeHint())
        self.devices.addItem(item)
        self.devices.setItemWidget(item, widget)

    def prune_nearby_devices(self) -> None:
        if self.workflow_active or self.receiving:
            return
        cutoff = time.monotonic() - 60
        self.radio_peers = {key: peer for key, peer in self.radio_peers.items() if peer["seen_at"] >= cutoff}
        if self.discovery:
            self.discovery.refresh_registration()
            self.discovery.prune()
        self.refresh_nearby_devices()

    @Slot(object)
    def handle_discovery(self, peers: list[DiscoveredPeer]) -> None:
        self.lan_peers = {peer.device_id: peer for peer in peers}
        for peer in peers:
            self.store.observe_peer(peer.device_id, ",".join(sorted(peer.capabilities)))
            # Discovery metadata is necessary but transfer authentication still
            # occurs through signed offers and pinned TLS.
            routes = self.discovery.routes_for(peer.device_id) if self.discovery else [peer]
            for route in routes:
                self.network.authorize_route(route.host, Transport.LAN,
                                             f"mdns:{peer.device_id}:{route.host}", ttl=240)
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
            peer["device_id"], peer.get("name") or "Nearby computer", peer["public_key"],
            transport=Transport.WIFI_DIRECT, capabilities=frozenset({"lan", "wifi_direct"}),
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
        descriptions = "\n".join(
            f"• {item['name']} — {_readable_size(int(item['size']))}" for item in files
        )
        total = _readable_size(sum(int(item["size"]) for item in files))
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Incoming files")
        dialog.setIcon(QMessageBox.Question)
        dialog.setText(
            f"{peer['name']} wants to send:\n\n{descriptions}\n\n"
            f"Total: {total}\nSave to Downloads?"
        )
        accept_button = dialog.addButton("Accept", QMessageBox.AcceptRole)
        dialog.addButton("Deny", QMessageBox.RejectRole)
        always_accept = QCheckBox("Always accept files from this device")
        always_accept.setChecked(False)
        dialog.setCheckBox(always_accept)
        QTimer.singleShot(300000, dialog.reject)
        dialog.exec()
        if dialog.clickedButton() is accept_button and not request.event.is_set():
            downloads = QStandardPaths.writableLocation(QStandardPaths.DownloadLocation)
            destination = Path(downloads) if downloads else Path.home() / "Downloads"
            destination.mkdir(parents=True, exist_ok=True)
            request.result = TransferApproval(str(destination), always_accept.isChecked())
            self.status.setText("Accepted. Receiving files into Downloads...")
        else:
            self.status.setText("Transfer declined.")
        request.event.set()

    @Slot(object)
    def update_progress(self, progress) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(progress.percent)
        if progress.direction != "receive":
            return
        self.receive_file_label.setText(
            f"Receiving {progress.current_file}  ·  File {progress.file_index} of {progress.total_files}"
        )
        self.receive_summary_label.setText(
            f"{progress.files_completed} of {progress.total_files} files complete  ·  "
            f"{_readable_size(progress.bytes_transferred)} of {_readable_size(progress.total_bytes)}  ·  "
            f"{progress.percent}%"
        )
        speed = (_readable_size(progress.bytes_per_second) + "/s"
                 if progress.bytes_per_second > 0 else "Calculating speed…")
        self.receive_rate_label.setText(f"{speed}  ·  {_readable_duration(progress.eta_seconds)}")
        self.receive_details.show()

    def reset_transfer_details(self) -> None:
        self.receive_file_label.clear()
        self.receive_summary_label.clear()
        self.receive_rate_label.clear()
        self.receive_details.hide()

    @Slot()
    def begin_receive(self) -> None:
        if self.workflow_active:
            return
        self.receiving = True
        self.set_busy(True)

    @Slot(object)
    def finish_receive(self, completion=None) -> None:
        if self.receiving:
            self.reset_workflow(reset_link=False)
        if completion is not None:
            file_word = "file" if completion.file_count == 1 else "files"
            self.status.setText(
                f"Received {completion.file_count} {file_word} from {completion.sender_name}. "
                f"Saved to {completion.destination}."
            )

    @Slot(bool)
    def finish_transfer(self, succeeded: bool) -> None:
        if succeeded:
            self.paths.clear()
            self.file_list.clear()
        self.reset_workflow()

    @Slot(object)
    def finish_transfer_result(self, result) -> None:
        if result.succeeded:
            recipient = (self.selected_endpoint or {}).get("name", "nearby device")
            file_count = len(self.paths)
            total_size = sum(path.stat().st_size for path in self.paths)
            elapsed = (time.monotonic() - self.send_started_at
                       if self.send_started_at is not None else 0.0)
            if file_count == 1:
                summary = f"{self.paths[0].name} ({_readable_size(total_size)})"
            else:
                summary = f"{file_count} files ({_readable_size(total_size)})"
            QMessageBox.information(
                self,
                "Files sent",
                f"{summary} sent to {recipient} in {_readable_elapsed(elapsed)}.",
            )
            self.finish_transfer(True)
            return
        if getattr(result, "cancelled", False):
            self.status.setText("Transfer canceled.")
            self.finish_transfer(False)
            return
        if (getattr(result, "may_fallback", False) and self.selected_endpoint
                and self.selected_endpoint.get("route") == "lan"):
            routes = self.selected_endpoint.get("lan_routes", [])
            next_index = int(self.selected_endpoint.get("lan_route_index", 0)) + 1
            if next_index < len(routes):
                self.selected_endpoint["lan_route_index"] = next_index
                self.status.setText("LAN endpoint unavailable; trying another address...")
                self._send_lan_route(routes[next_index])
                return
        if (getattr(result, "may_fallback", False) and self.selected_endpoint
                and self.selected_endpoint.get("route") == "lan" and self.radio):
            match = next(((radio_id, peer) for radio_id, peer in self.radio_peers.items()
                          if peer.get("device_id") == self.selected_endpoint["device_id"]), None)
            if match and self.selected_endpoint.get("supports_wifi_direct", False):
                radio_id, peer = match
                self.pending_radio_id = radio_id
                self.selected_endpoint = dict(peer)
                self.send_started = False
                self.set_transfer_transport(Transport.WIFI_DIRECT)
                self.status.setText("LAN unavailable; trying Wi-Fi Direct...")
                try:
                    self.radio.connect_wifi_direct(radio_id, self.attempt_id)
                    return
                except RuntimeError as exc:
                    self.status.setText(f"Wi-Fi Direct fallback failed: {exc}")
        if self.selected_endpoint and self.selected_endpoint.get("route") == "lan":
            self.status.setText("Could not reach this device on the LAN. Check that both devices are on the same subnet and allow the app through the firewall.")
        self.finish_transfer(False)

    def reset_workflow(self, reset_link: bool = True) -> None:
        if self.scan_timer:
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
        self.send_started_at = None
        self.set_transfer_transport(None)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.reset_transfer_details()
        self.set_busy(False)
        if reset_link:
            self.network.clear_links()
        if reset_link and self.radio and hasattr(self.radio, "reset_wifi_direct"):
            try:
                self.radio.reset_wifi_direct()
            except Exception as exc:
                logger.warning("Error resetting Wi-Fi Direct on radio: %s", exc)
        self.refresh_nearby_devices()
        if self.scan_timer:
            QTimer.singleShot(2000, self.scan_timer.start)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._closing = True
        self.update_receive_status("unavailable")
        self.refresh_animation_timer.stop()
        if self.scan_timer:
            self.scan_timer.stop()
        self.expiry_timer.stop()
        if self.radio:
            self.radio.close()
        discovery, self.discovery = self.discovery, None
        if discovery:
            threading.Thread(target=discovery.close, daemon=True,
                             name="lan-discovery-close").start()
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
