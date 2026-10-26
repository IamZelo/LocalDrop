from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import socket
import ssl
import tempfile
import threading
import time
import uuid
from pathlib import Path
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .discovery import DiscoveredPeer
from .connectivity import TransferPhase, TransferResult, Transport
from .identity import Identity, export_private_key_pem, unb64, verify
from .protocol import CHUNK_SIZE, canonical, hash_file, recv_frame, send_chunk, send_control, unique_destination, validate_manifest
from .storage import LocalStore


logger = logging.getLogger("secure_share.network")
CONNECT_TIMEOUT = 20
CONNECT_ATTEMPTS = 4
CONNECT_RETRY_DELAY = 2
APPROVAL_TIMEOUT = 330
STREAM_TIMEOUT = 60


class NetworkError(Exception):
    def __init__(self, message: str, *, phase: str = "connect", retryable: bool = False,
                 offer_sent: bool = False):
        super().__init__(message)
        self.phase, self.retryable, self.offer_sent = phase, retryable, offer_sent


@dataclass(frozen=True)
class RouteAuthorization:
    remote_address: str
    transport: Transport
    session_id: str
    expires_at: float
    local_address: str | None = None


class InteractionCallbacks:
    def __init__(self, accept_transfer: Callable[[dict, list[dict]], str | None],
                 status: Callable[[str], None], progress: Callable[[str, int], None],
                 transfer_finished: Callable[[bool], None],
                 receive_finished: Callable[[], None] = lambda: None,
                 result_finished: Callable[[TransferResult], None] | None = None):
        self.accept_transfer = accept_transfer
        self.status = status
        self.progress = progress
        self.transfer_finished = transfer_finished
        self.receive_finished = receive_finished
        self.result_finished = result_finished


def _local_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])
    return ip.is_private or ip.is_link_local or ip.is_loopback


def _identity_payload(identity: Identity) -> dict:
    return {"device_id": identity.device_id, "name": identity.display_name, "public_key": identity.public_b64}


class NetworkManager:
    def __init__(self, identity: Identity, store: LocalStore, callbacks: InteractionCallbacks):
        self.identity = identity
        self.store = store
        self.callbacks = callbacks
        self.running = True
        self._link_condition = threading.Condition()
        self._links: set[tuple[str, str]] = set()
        self._authorizations: dict[tuple[str, str], RouteAuthorization] = {}
        self._send_lock = threading.Lock()
        self._receive_lock = threading.Lock()
        self._server_context = self._make_server_context()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("0.0.0.0", 0))
        self.listener.listen(16)
        self.listener.settimeout(1)
        self.port = self.listener.getsockname()[1]
        logger.info("File listener ready on 0.0.0.0:%d (TLS 1.3)", self.port)
        threading.Thread(target=self._accept_loop, daemon=True, name="share-listener").start()

    def _make_server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        handle = tempfile.NamedTemporaryFile(prefix="lss-key-", suffix=".pem", delete=False)
        try:
            handle.write(export_private_key_pem(self.identity))
            handle.close()
            context.load_cert_chain(str(self.identity.certificate_path), handle.name)
        finally:
            try:
                os.unlink(handle.name)
            except OSError:
                pass
        return context

    def _connect(self, peer: DiscoveredPeer, expected_public_key: str | None = None,
                 timeout: float = CONNECT_TIMEOUT, local_address: str | None = None):
        if not _local_address(peer.host):
            raise NetworkError("Refusing an address that is not local or link-local")
        raw = socket.socket(socket.AF_INET6 if ":" in peer.host else socket.AF_INET, socket.SOCK_STREAM)
        wrapped = None
        phase = "tcp_connect"
        try:
            raw.settimeout(timeout)
            if local_address:
                raw.bind((local_address, 0))
            logger.info("TCP connecting local=%s remote=%s:%d timeout=%ss", local_address, peer.host, peer.port, timeout)
            raw.connect((peer.host, peer.port))
            phase = "tls_handshake"
            self.callbacks.status("Wi-Fi connected. Establishing the encrypted file connection...")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            wrapped = context.wrap_socket(raw, server_hostname=None)
            cert = x509.load_der_x509_certificate(wrapped.getpeercert(binary_form=True))
            raw_key = cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if expected_public_key and raw_key != unb64(expected_public_key):
                raise NetworkError("The remote device identity changed; transfer stopped")
            logger.info("TLS established remote=%s:%d", peer.host, peer.port)
            return wrapped
        except Exception as exc:
            logger.exception("Connection failed phase=%s remote=%s:%d local=%s", phase, peer.host, peer.port, local_address)
            (wrapped or raw).close()
            hint = " Check the receiver app and Windows Firewall access for Python." if phase == "tcp_connect" else ""
            raise NetworkError(f"{phase} to {peer.host}:{peer.port}: {exc}.{hint}", phase=phase,
                               retryable=phase == "tcp_connect") from exc

    def authorize_route(self, remote_address: str, transport: Transport, session_id: str,
                        ttl: float = 120, local_address: str | None = None) -> None:
        if not _local_address(remote_address):
            raise ValueError("Route authorization must use a local address")
        authorization = RouteAuthorization(remote_address, transport, session_id,
                                           time.monotonic() + ttl, local_address)
        with self._link_condition:
            self._authorizations[(remote_address, session_id)] = authorization
            self._link_condition.notify_all()

    def register_link(self, local_address: str, remote_address: str) -> None:
        """Compatibility wrapper for a Wi-Fi Direct route authorization."""
        self.authorize_route(remote_address, Transport.WIFI_DIRECT, "wifi-direct", 330, local_address)

    def clear_links(self) -> None:
        with self._link_condition:
            self._links.clear()
            self._authorizations.clear()

    def _accept_loop(self) -> None:
        while self.running:
            try:
                client, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle_client, args=(client, address), daemon=True).start()

    def _handle_client(self, raw, address) -> None:
        endpoint = (raw.getsockname()[0], address[0])
        with self._link_condition:
            # A queued Qt endpoint notification may arrive just after TCP accept.
            def authorized():
                now = time.monotonic()
                self._authorizations = {key: value for key, value in self._authorizations.items()
                                        if value.expires_at > now}
                return any(value.remote_address == address[0] for value in self._authorizations.values())
            allowed = self._link_condition.wait_for(
                lambda: authorized() or not self.running,
                2,
            )
            allowed = allowed and self.running and authorized()
        if not allowed:
            logger.warning("Rejected socket outside an authorized transfer route: %s", endpoint)
            raw.close()
            return
        sock = None
        receiving = False
        try:
            raw.settimeout(CONNECT_TIMEOUT)
            logger.info("Incoming TCP connection from %s", address)
            sock = self._server_context.wrap_socket(raw, server_side=True)
            sock.settimeout(APPROVAL_TIMEOUT)
            kind, first = recv_frame(sock)
            if kind != "json":
                raise NetworkError("Expected a control message")
            if first.get("type") == "offer":
                receiving = self._receive_lock.acquire(blocking=False)
                if not receiving:
                    send_control(sock, {"type": "decision", "accepted": False, "reason": "Receiver is busy"})
                    return
                self._receive_files(sock, first)
            else:
                raise NetworkError("Unknown request")
        except Exception as exc:
            logger.exception("Incoming transfer failed remote=%s", address)
            self.callbacks.status(f"Incoming connection failed: {exc}")
        finally:
            if receiving:
                self._receive_lock.release()
            if receiving or not self._receive_lock.locked():
                self.callbacks.receive_finished()
            try:
                (sock or raw).close()
            except OSError:
                pass


    def send_files(self, peer: DiscoveredPeer, paths: list[Path], *,
                   expected_public_key: str | None = None, local_address: str | None = None) -> None:
        if not self._send_lock.acquire(blocking=False):
            logger.warning("Ignoring duplicate send request for %s", peer.device_id)
            return
        def work():
            transfer_id = uuid.uuid4().hex
            succeeded = False
            offer_sent = False
            failure: Exception | None = None
            sock = None
            phase = "manifest"
            try:
                trusted = self.store.peer(peer.device_id)
                if not expected_public_key and not trusted:
                    raise NetworkError("Missing receiver public key; rediscover the device")
                if trusted and (trusted["blocked"] or (expected_public_key and trusted["public_key"] != expected_public_key)):
                    raise NetworkError("Device blocked or identity changed")
                self.callbacks.status("Preparing file manifest and checksums...")
                files = [{"name": p.name, "size": p.stat().st_size, "sha256": hash_file(p)} for p in paths]
                offer = {
                    "type": "offer", "version": 1, "transfer_id": transfer_id,
                    "sender": _identity_payload(self.identity), "files": files, "time": int(time.time()),
                }
                offer["signature"] = self.identity.sign(canonical(offer))
                phase = "connect"
                self.callbacks.status(f"Connecting to file server {peer.host}:{peer.port}...")
                connect_error = None
                for attempt in range(1, CONNECT_ATTEMPTS + 1):
                    try:
                        self.callbacks.status(
                            f"Connecting to file server ({attempt}/{CONNECT_ATTEMPTS})..."
                        )
                        sock = self._connect(
                            peer,
                            trusted["public_key"] if trusted else expected_public_key,
                            timeout=8,
                            local_address=local_address,
                        )
                        break
                    except NetworkError as exc:
                        connect_error = exc
                        if attempt == CONNECT_ATTEMPTS:
                            raise
                        logger.warning(
                            "Wi-Fi Direct route is not ready; retrying TCP connection in %ss: %s",
                            CONNECT_RETRY_DELAY,
                            exc,
                        )
                        time.sleep(CONNECT_RETRY_DELAY)
                if sock is None and connect_error:
                    raise connect_error
                phase = "receiver_approval"
                sock.settimeout(APPROVAL_TIMEOUT)
                self.callbacks.status("File offer sent. Waiting for the receiver to accept (up to 5 minutes)...")
                logger.info("Transfer %s waiting for approval remote=%s:%d", transfer_id, peer.host, peer.port)
                send_control(sock, offer)
                offer_sent = True
                _, decision = recv_frame(sock)
                if not decision.get("accepted"):
                    raise NetworkError(decision.get("reason", "Transfer declined"))
                if not trusted and expected_public_key:
                    self.store.trust_peer(peer.device_id, peer.display_name, expected_public_key)
                phase = "file_stream"
                sock.settimeout(STREAM_TIMEOUT)
                self.callbacks.status("Accepted. Sending files...")
                total = sum(item["size"] for item in files) or 1
                sent = 0
                for index, path in enumerate(paths):
                    send_control(sock, {"type": "file_start", "index": index})
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
                            send_chunk(sock, chunk)
                            sent += len(chunk)
                            self.callbacks.progress(transfer_id, int(sent * 100 / total))
                    send_control(sock, {"type": "file_end", "index": index})
                send_control(sock, {"type": "transfer_end"})
                phase = "receiver_verification"
                self.callbacks.status("Files sent. Waiting for receiver verification...")
                _, result = recv_frame(sock)
                if result.get("status") != "complete":
                    raise NetworkError(result.get("reason", "Receiver could not verify the files"))
                self.store.record_transfer(transfer_id, peer.device_id, "sent", {"files": files}, "complete")
                recipient_name = trusted["name"] if trusted else peer.display_name
                self.callbacks.status(f"Sent {len(files)} file(s) to {recipient_name}")
                self.callbacks.progress(transfer_id, 100)
                succeeded = True
            except Exception as exc:
                failure = exc
                logger.exception("Transfer %s failed phase=%s remote=%s:%d", transfer_id, phase, peer.host, peer.port)
                self.callbacks.status(f"Transfer failed during {phase}: {exc}")
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
                self._send_lock.release()
                if self.callbacks.result_finished:
                    phase_value = next((value for value in TransferPhase if value.value == phase), TransferPhase.CONNECT)
                    retryable = isinstance(failure, NetworkError) and getattr(failure, "retryable", False)
                    self.callbacks.result_finished(TransferResult(succeeded, TransferPhase.COMPLETE if succeeded else phase_value,
                                                                  retryable, offer_sent, "" if succeeded else str(failure)))
                self.callbacks.transfer_finished(succeeded)
        threading.Thread(target=work, daemon=True).start()

    def _receive_files(self, sock, offer: dict) -> None:
        signature = offer.pop("signature", "")
        sender = offer.get("sender", {})
        device_id = str(sender.get("device_id") or "")
        sender_name = str(sender.get("name") or "Nearby device")
        sender_public_key = str(sender.get("public_key") or "")
        if not device_id or not sender_public_key:
            send_control(sock, {"type": "decision", "accepted": False, "reason": "Invalid sender identity"})
            return
        trusted = self.store.peer(device_id)
        if trusted and (trusted["blocked"] or trusted["public_key"] != sender_public_key):
            send_control(sock, {"type": "decision", "accepted": False, "reason": "Device identity changed"})
            return
        # A first transfer is trust-on-accept: prove ownership of the public key
        # in the signed offer, then store it only if the receiver accepts.
        verify(trusted["public_key"] if trusted else sender_public_key, signature, canonical(offer))
        if abs(int(time.time()) - int(offer.get("time", 0))) > 300:
            raise NetworkError("Stale transfer offer")
        try:
            uuid.UUID(hex=offer.get("transfer_id", ""))
        except (ValueError, TypeError):
            raise NetworkError("Invalid transfer identifier")
        offer["files"] = validate_manifest(offer.get("files"))
        offered_by = trusted or {
            "device_id": device_id,
            "name": sender_name,
            "public_key": sender_public_key,
            "blocked": False,
        }
        logger.info("Incoming offer transfer=%s sender=%s files=%d", offer["transfer_id"], sender_name, len(offer["files"]))
        folder = self.callbacks.accept_transfer(offered_by, offer["files"])
        if not folder:
            send_control(sock, {"type": "decision", "accepted": False, "reason": "Transfer declined"})
            return
        destination_dir = Path(folder)
        destination_dir.mkdir(parents=True, exist_ok=True)
        if not trusted:
            self.store.trust_peer(device_id, sender_name, sender_public_key)
            trusted = self.store.peer(device_id)
        required = sum(int(item["size"]) for item in offer["files"])
        if required > __import__("shutil").disk_usage(destination_dir).free:
            send_control(sock, {"type": "decision", "accepted": False, "reason": "Insufficient disk space"})
            return
        sock.settimeout(STREAM_TIMEOUT)
        self.callbacks.status("Receiving files into Downloads...")
        send_control(sock, {"type": "decision", "accepted": True})
        total = required or 1
        received = 0
        completed = []
        for expected_index, manifest in enumerate(offer["files"]):
            kind, start = recv_frame(sock)
            if kind != "json" or start != {"index": expected_index, "type": "file_start"}:
                raise NetworkError("Invalid file sequence")
            destination = unique_destination(destination_dir, manifest["name"])
            partial = destination.with_suffix(destination.suffix + ".part")
            digest = hashlib.sha256()
            count = 0
            try:
                with partial.open("xb") as output:
                    while count < manifest["size"]:
                        kind, chunk = recv_frame(sock)
                        if kind != "chunk" or count + len(chunk) > manifest["size"]:
                            raise NetworkError("Invalid file chunk")
                        output.write(chunk)
                        digest.update(chunk)
                        count += len(chunk)
                        received += len(chunk)
                        self.callbacks.progress(offer["transfer_id"], int(received * 100 / total))
                kind, end = recv_frame(sock)
                if kind != "json" or end != {"index": expected_index, "type": "file_end"}:
                    raise NetworkError("Missing file terminator")
                if digest.hexdigest() != manifest["sha256"]:
                    raise NetworkError("File integrity verification failed")
                partial.replace(destination)
                completed.append(str(destination))
            except Exception:
                partial.unlink(missing_ok=True)
                raise
        _, end = recv_frame(sock)
        if end.get("type") != "transfer_end":
            raise NetworkError("Missing transfer terminator")
        send_control(sock, {"type": "result", "status": "complete"})
        self.store.record_transfer(offer["transfer_id"], sender["device_id"], "received", {"files": offer["files"]}, "complete")
        self.callbacks.status(f"Received {len(completed)} file(s) from {sender_name}")
        self.callbacks.progress(offer["transfer_id"], 100)

    def close(self) -> None:
        self.running = False
        with self._link_condition:
            self._links.clear()
            self._link_condition.notify_all()
        self.listener.close()
