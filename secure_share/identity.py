from __future__ import annotations

import base64
import json
import os
import socket
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import keyring
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

SERVICE = "LocalSecureShare"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def app_data_dir() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library/Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    path = root / "LocalSecureShare"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass(frozen=True)
class Identity:
    device_id: str
    display_name: str
    private_key: Ed25519PrivateKey
    certificate_path: Path
    fallback_storage: bool = False

    @property
    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def public_b64(self) -> str:
        return b64(self.public_bytes)

    def sign(self, payload: bytes) -> str:
        return b64(self.private_key.sign(payload))


def verify(public_b64: str, signature_b64: str, payload: bytes) -> None:
    Ed25519PublicKey.from_public_bytes(unb64(public_b64)).verify(unb64(signature_b64), payload)


def _read_secret(device_id: str, data_dir: Path) -> tuple[bytes | None, bool]:
    try:
        value = keyring.get_password(SERVICE, device_id)
        if value:
            return unb64(value), False
    except Exception:
        pass
    fallback = data_dir / "identity.key"
    if fallback.exists():
        return fallback.read_bytes(), True
    return None, False


def _write_secret(device_id: str, secret: bytes, data_dir: Path) -> bool:
    try:
        keyring.set_password(SERVICE, device_id, b64(secret))
        return False
    except Exception:
        fallback = data_dir / "identity.key"
        fallback.write_bytes(secret)
        try:
            fallback.chmod(0o600)
        except OSError:
            pass
        return True


def load_or_create_identity(display_name: str | None = None) -> Identity:
    data_dir = app_data_dir()
    profile_path = data_dir / "profile.json"
    if profile_path.exists():
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        device_id = profile["device_id"]
        name = profile.get("display_name") or socket.gethostname()
    else:
        device_id = b64(os.urandom(18))
        name = display_name or socket.gethostname()
        profile_path.write_text(
            json.dumps({"device_id": device_id, "display_name": name}, indent=2), encoding="utf-8"
        )

    raw, fallback = _read_secret(device_id, data_dir)
    if raw is None:
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        fallback = _write_secret(device_id, raw, data_dir)
    private = Ed25519PrivateKey.from_private_bytes(raw)
    cert_path = data_dir / "identity.crt"
    certificate_matches = False
    if cert_path.exists():
        try:
            certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
            certificate_matches = certificate.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ) == private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        except (ValueError, TypeError):
            certificate_matches = False
    if not certificate_matches:
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
            .sign(private, algorithm=None)
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return Identity(device_id, name, private, cert_path, fallback)


def export_private_key_pem(identity: Identity) -> bytes:
    return identity.private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
