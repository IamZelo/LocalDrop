"""Load application logic with optional GUI/crypto/native boundaries stubbed.

These tests exercise production control flow, not Windows drivers or Qt rendering.
"""
import base64
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock, patch
from dataclasses import dataclass

@dataclass
class Peer:
    service_name: str
    host: str
    port: int
    device_id: str
    display_name: str
    public_key: str = ""
    protocol_version: int = 1
    transport: object = None
    local_interface: str | None = None
    fresh_at: float = 0.0
    capabilities: frozenset[str] = frozenset({"lan"})

def module(name, **values):
    result = types.ModuleType(name)
    result.__dict__.update(values)
    return result

def load(name):
    b64 = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    unb64 = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    identity = module("secure_share.identity", b64=b64, unb64=unb64, Identity=object,
        load_or_create_identity=Mock(), export_private_key_pem=Mock(), verify=Mock())
    replacements = {
        "secure_share.identity": identity,
        "secure_share.storage": module("secure_share.storage", LocalStore=Mock()),
        "secure_share.discovery": module("secure_share.discovery", DiscoveredPeer=Peer),
    }
    if name == "app":
        core = module("PySide6.QtCore", QObject=object, QStandardPaths=Mock(),
            Qt=types.SimpleNamespace(UserRole=1, ItemIsEnabled=2, ItemIsSelectable=4, CustomContextMenu=3), QTimer=Mock(),
            Signal=lambda *args: Mock(), Slot=lambda *args: lambda fn: fn)
        gui = module("PySide6.QtGui", QColor=Mock(), QCloseEvent=object, QDragEnterEvent=object, QDropEvent=object)
        widgets = module("PySide6.QtWidgets", **{key: type(key, (), {}) for key in
            ("QApplication", "QFileDialog", "QHBoxLayout", "QLabel", "QListWidget", "QListWidgetItem",
             "QMainWindow", "QMessageBox", "QProgressBar", "QPushButton", "QVBoxLayout", "QWidget",
             "QCheckBox", "QMenu")})
        replacements.update({"PySide6": module("PySide6"), "PySide6.QtCore": core,
            "PySide6.QtGui": gui, "PySide6.QtWidgets": widgets,
            "qasync": module("qasync", QEventLoop=Mock()),
            "secure_share.network": module("secure_share.network", NetworkManager=Mock(), InteractionCallbacks=Mock(),
                TransferApproval=type("TransferApproval", (), {}))})
    if name == "network":
        replacements.update({"cryptography": module("cryptography", x509=Mock()),
            "cryptography.hazmat": module("cryptography.hazmat"),
            "cryptography.hazmat.primitives": module("cryptography.hazmat.primitives", serialization=Mock())})
    target = "secure_share._tested_" + name
    spec = importlib.util.spec_from_file_location(target, Path(__file__).resolve().parents[1] / "secure_share" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {**replacements, target: result}):
        spec.loader.exec_module(result)
    return result
