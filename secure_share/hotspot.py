from __future__ import annotations

import base64
import asyncio
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import Identity, b64, unb64, verify
from .protocol import canonical

REQUEST_VERSION = 2
REQUEST_MAX_AGE = 30


@dataclass(frozen=True)
class SessionCredentials:
    ssid: str
    passphrase: str


def new_hotspot_request(identity: Identity, target_device_id: str, nonce: bytes | None = None):
    private = X25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    request = {"v": REQUEST_VERSION, "kind": "hotspot_request", "sender": identity.device_id,
               "target": target_device_id, "time": int(time.time()), "nonce": b64(nonce or os.urandom(16)),
               "ephemeral_key": b64(public), "public_key": identity.public_b64}
    request["signature"] = identity.sign(canonical(request))
    return request, private


def validate_hotspot_request(request: dict, own_device_id: str, seen_nonces: set[str], now: int | None = None) -> dict:
    value = dict(request)
    signature = str(value.pop("signature", ""))
    if value.get("v") != REQUEST_VERSION or value.get("kind") != "hotspot_request":
        raise ValueError("Unsupported hotspot request")
    if value.get("target") != own_device_id:
        raise ValueError("Hotspot request targets another device")
    timestamp = int(value.get("time", 0))
    if abs((now or int(time.time())) - timestamp) > REQUEST_MAX_AGE:
        raise ValueError("Expired hotspot request")
    nonce = str(value.get("nonce", ""))
    if not nonce or nonce in seen_nonces:
        raise ValueError("Replayed hotspot request")
    if len(unb64(str(value.get("ephemeral_key", "")))) != 32:
        raise ValueError("Invalid ephemeral key")
    verify(str(value.get("public_key", "")), signature, canonical(value))
    seen_nonces.add(nonce)
    return value


def derive_credentials(private: X25519PrivateKey, peer_public_b64: str, nonce_b64: str) -> SessionCredentials:
    shared = private.exchange(X25519PublicKey.from_public_bytes(unb64(peer_public_b64)))
    material = HKDF(algorithm=hashes.SHA256(), length=32, salt=unb64(nonce_b64),
                    info=b"local-secure-share/hotspot/v2").derive(shared)
    token = base64.b32encode(material).decode("ascii").rstrip("=")
    return SessionCredentials(f"LSS-{token[:12]}", token[12:32])


class HotspotBackend:
    """Windows 11 packaged-app boundary. Unpackaged runs fail closed and keep LAN/direct usable."""

    def __init__(self, journal_path: Path, *, start_operation=None, join_operation=None,
                 stop_operation=None, restore_operation=None):
        self.journal_path = journal_path
        self.created_session = False
        self._start_operation = start_operation
        self._join_operation = join_operation
        self._stop_operation = stop_operation
        self._restore_operation = restore_operation
        self.original_network: dict | None = None

    def capability(self) -> tuple[bool, str]:
        try:
            from winrt.windows.applicationmodel import Package
            Package.current.id.name
            from winrt.windows.networking.networkoperators import NetworkOperatorTetheringManager  # noqa: F401
            from winrt.windows.devices.wifi import WiFiAdapter  # noqa: F401
        except Exception:
            return False, "Hotspot automation requires the signed MSIX and wiFiControl permission"
        return True, "available"

    async def recover(self) -> None:
        if self.journal_path.exists():
            state = json.loads(self.journal_path.read_text(encoding="utf-8"))
            if self._restore_operation and state.get("original_network") is not None:
                await asyncio.wait_for(self._restore_operation(state["original_network"]), 30)
            if self._stop_operation and state.get("created_session"):
                await asyncio.wait_for(self._stop_operation(), 30)
            self.journal_path.unlink(missing_ok=True)

    def record(self, state: dict) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        self.journal_path.write_text(json.dumps(state), encoding="utf-8")

    async def start(self, credentials: SessionCredentials, timeout: float = 30) -> None:
        if not self._start_operation:
            raise RuntimeError(self.capability()[1])
        # The operation must report whether it created this session. Never claim
        # ownership of a hotspot that was already active.
        created = await asyncio.wait_for(self._start_operation(credentials), timeout)
        if not created:
            raise RuntimeError("A pre-existing hotspot is active; it was left unchanged")
        self.created_session = True
        self.record({"created_session": True, "original_network": self.original_network})

    async def join(self, credentials: SessionCredentials, original_network: dict,
                   timeout: float = 45) -> None:
        if not self._join_operation:
            raise RuntimeError(self.capability()[1])
        self.original_network = original_network
        self.record({"created_session": self.created_session, "original_network": original_network})
        await asyncio.wait_for(self._join_operation(credentials, "manual"), timeout)

    async def stop(self, timeout: float = 30) -> None:
        if self.created_session and self._stop_operation:
            await asyncio.wait_for(self._stop_operation(), timeout)
        self.created_session = False

    async def restore(self, timeout: float = 30) -> None:
        if self.original_network is not None and self._restore_operation:
            await asyncio.wait_for(self._restore_operation(self.original_network), timeout)
        self.original_network = None

    async def close(self) -> None:
        try:
            await self.stop()
        finally:
            await self.restore()
            self.journal_path.unlink(missing_ok=True)
