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
from collections import deque
from pathlib import Path
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .discovery import DiscoveredPeer
from .connectivity import TransferPhase, TransferResult, Transport
from .identity import Identity, export_private_key_pem, unb64, verify
from .protocol import CHUNK_SIZE, canonical, recv_frame, send_chunk, send_control, unique_destination, validate_manifest
from .storage import LocalStore


logger = logging.getLogger("secure_share.network")
CONNECT_TIMEOUT = 20
CONNECT_ATTEMPTS = 4
CONNECT_RETRY_DELAY = 2
APPROVAL_TIMEOUT = 330
STREAM_TIMEOUT = 60


@dataclass(frozen=True)
class TransferApproval:
    destination: str
    always_accept: bool = False


@dataclass(frozen=True)
class TransferProgress:
    transfer_id: str
    direction: str
    current_file: str
    file_index: int
    total_files: int
    files_completed: int
    bytes_transferred: int
    total_bytes: int
    percent: int
    bytes_per_second: float
    eta_seconds: float | None


@dataclass(frozen=True)
class ReceiveCompletion:
    sender_name: str
    file_count: int
    total_bytes: int
    destination: str


class _ProgressTracker:
    """Build throttled progress snapshots from a short rolling speed window."""

    def __init__(self, callback: Callable[[TransferProgress], None], transfer_id: str,
                 direction: str, total_bytes: int, total_files: int):
        self.callback = callback
        self.transfer_id = transfer_id
        self.direction = direction
        self.total_bytes = total_bytes
        self.total_files = total_files
        now = time.monotonic()
        self.samples: deque[tuple[float, int]] = deque([(now, 0)])
        self.last_emit = 0.0

    def update(self, bytes_transferred: int, current_file: str, file_index: int,
               files_completed: int, *, force: bool = False) -> None:
        now = time.monotonic()
        self.samples.append((now, bytes_transferred))
        cutoff = now - 2.0
        while len(self.samples) > 2 and self.samples[1][0] <= cutoff:
            self.samples.popleft()
        if not force and now - self.last_emit < 0.2:
            return
        started_at, started_bytes = self.samples[0]
        elapsed = now - started_at
        speed = ((bytes_transferred - started_bytes) / elapsed) if elapsed > 0 else 0.0
        remaining = max(0, self.total_bytes - bytes_transferred)
        eta = remaining / speed if speed > 0 else None
        if self.total_bytes:
            percent = min(100, int(bytes_transferred * 100 / self.total_bytes))
        else:
            percent = 100 if files_completed >= self.total_files else 0
        self.callback(TransferProgress(
            self.transfer_id, self.direction, current_file, file_index,
            self.total_files, files_completed, bytes_transferred, self.total_bytes,
            percent, speed, eta,
        ))
        self.last_emit = now


class NetworkError(Exception):
    def __init__(self, message: str, *, phase: str = "connect", retryable: bool = False,
                 offer_sent: bool = False):
        super().__init__(message)
        self.phase, self.retryable, self.offer_sent = phase, retryable, offer_sent


class TransferCancelled(NetworkError):
    def __init__(self, phase: str = "file_stream"):
        super().__init__("Transfer canceled", phase=phase)


@dataclass(frozen=True)
class RouteAuthorization:
    remote_address: str
    transport: Transport
    session_id: str
    expires_at: float
    local_address: str | None = None


class InteractionCallbacks:
    def __init__(self, accept_transfer: Callable[[dict, list[dict]], TransferApproval | str | None],
                 status: Callable[[str], None], progress: Callable[[TransferProgress], None],
                 transfer_finished: Callable[[bool], None],
                 receive_finished: Callable[[ReceiveCompletion | None], None] = lambda _result: None,
                 result_finished: Callable[[TransferResult], None] | None = None,
                 route_started: Callable[[Transport], None] | None = None,
                 trust_changed: Callable[[], None] | None = None,
                 receive_started: Callable[[], None] | None = None):
        self.accept_transfer = accept_transfer
        self.status = status
        self.progress = progress
        self.transfer_finished = transfer_finished
        self.receive_finished = receive_finished
        self.result_finished = result_finished
        self.route_started = route_started
        self.trust_changed = trust_changed
        self.receive_started = receive_started


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
        self._transfer_state_lock = threading.Lock()
        self._send_cancel_event: threading.Event | None = None
        self._receive_cancel_event: threading.Event | None = None
        self._send_socket = None
        self._receive_socket = None
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

    def _set_transfer_socket(self, direction: str, sock) -> None:
        with self._transfer_state_lock:
            setattr(self, f"_{direction}_socket", sock)

    def _clear_transfer_state(self, direction: str, cancel_event: threading.Event) -> None:
        with self._transfer_state_lock:
            if getattr(self, f"_{direction}_cancel_event") is cancel_event:
                setattr(self, f"_{direction}_cancel_event", None)
                setattr(self, f"_{direction}_socket", None)

    @staticmethod
    def _check_cancelled(cancel_event: threading.Event, phase: str) -> None:
        if cancel_event.is_set():
            raise TransferCancelled(phase)

    def cancel_active_transfer(self) -> bool:
        """Cancel active network work and close sockets to interrupt blocking I/O."""
        with self._transfer_state_lock:
            active = False
            sockets = []
            for direction in ("send", "receive"):
                event = getattr(self, f"_{direction}_cancel_event")
                if event is not None:
                    event.set()
                    active = True
                sock = getattr(self, f"_{direction}_socket")
                if sock is not None:
                    sockets.append(sock)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        return active

    def _connect(self, peer: DiscoveredPeer, expected_public_key: str | None = None,
                 timeout: float = CONNECT_TIMEOUT, local_address: str | None = None,
                 cancel_event: threading.Event | None = None):
        if not _local_address(peer.host):
            raise NetworkError("Refusing an address that is not local or link-local")
        raw = socket.socket(socket.AF_INET6 if ":" in peer.host else socket.AF_INET, socket.SOCK_STREAM)
        wrapped = None
        phase = "tcp_connect"
        try:
            if cancel_event:
                self._check_cancelled(cancel_event, phase)
                self._set_transfer_socket("send", raw)
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
            if cancel_event:
                self._set_transfer_socket("send", wrapped)
                self._check_cancelled(cancel_event, phase)
            cert = x509.load_der_x509_certificate(wrapped.getpeercert(binary_form=True))
            raw_key = cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if expected_public_key and raw_key != unb64(expected_public_key):
                raise NetworkError("The remote device identity changed; transfer stopped")
            logger.info("TLS established remote=%s:%d", peer.host, peer.port)
            return wrapped
        except Exception as exc:
            logger.exception("Connection failed phase=%s remote=%s:%d local=%s", phase, peer.host, peer.port, local_address)
            (wrapped or raw).close()
            if cancel_event and cancel_event.is_set():
                raise TransferCancelled(phase) from exc
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
        logger.debug("Authorized %s route remote=%s session=%s ttl=%ss",
                     transport.value, remote_address, session_id, ttl)

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
            def matching_authorization() -> RouteAuthorization | None:
                now = time.monotonic()
                self._authorizations = {key: value for key, value in self._authorizations.items()
                                        if value.expires_at > now}
                return next((value for value in self._authorizations.values()
                             if value.remote_address == address[0]), None)
            allowed = self._link_condition.wait_for(
                lambda: matching_authorization() is not None or not self.running,
                2,
            )
            authorization = matching_authorization() if allowed and self.running else None
            allowed = authorization is not None
        if not allowed:
            with self._link_condition:
                expected = sorted({value.remote_address for value in self._authorizations.values()})
            logger.warning("Rejected socket outside an authorized transfer route: %s; expected sources=%s",
                           endpoint, expected)
            raw.close()
            return
        sock = None
        receiving = self._receive_lock.acquire(blocking=False)
        if not receiving:
            logger.info("Rejected incoming socket because the receiver is busy: %s", address)
            raw.close()
            return
        cancel_event = threading.Event()
        with self._transfer_state_lock:
            self._receive_cancel_event = cancel_event
            self._receive_socket = raw
        completion = None
        try:
            if self.callbacks.route_started and authorization:
                self.callbacks.route_started(authorization.transport)
            raw.settimeout(CONNECT_TIMEOUT)
            logger.info("Incoming TCP connection from %s", address)
            sock = self._server_context.wrap_socket(raw, server_side=True)
            self._set_transfer_socket("receive", sock)
            self._check_cancelled(cancel_event, "tls_handshake")
            sock.settimeout(APPROVAL_TIMEOUT)
            kind, first = recv_frame(sock)
            if kind != "json":
                raise NetworkError("Expected a control message")
            if first.get("type") == "offer":
                completion = self._receive_files(sock, first, cancel_event)
            else:
                raise NetworkError("Unknown request")
        except TransferCancelled:
            logger.info("Incoming transfer canceled remote=%s", address)
            self.callbacks.status("Transfer canceled.")
        except Exception as exc:
            if cancel_event.is_set():
                logger.info("Incoming transfer canceled remote=%s", address)
                self.callbacks.status("Transfer canceled.")
            else:
                logger.exception("Incoming transfer failed remote=%s", address)
                self.callbacks.status(f"Incoming connection failed: {exc}")
        finally:
            self._clear_transfer_state("receive", cancel_event)
            if receiving:
                self._receive_lock.release()
            if receiving or not self._receive_lock.locked():
                self.callbacks.receive_finished(completion)
            try:
                (sock or raw).close()
            except OSError:
                pass


    def send_files(self, peer: DiscoveredPeer, paths: list[Path], *,
                   expected_public_key: str | None = None, local_address: str | None = None) -> None:
        if not self._send_lock.acquire(blocking=False):
            logger.warning("Ignoring duplicate send request for %s", peer.device_id)
            return
        cancel_event = threading.Event()
        with self._transfer_state_lock:
            self._send_cancel_event = cancel_event
            self._send_socket = None
        def work():
            transfer_id = uuid.uuid4().hex
            route_started = time.monotonic()
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
                files = []
                for path in paths:
                    self._check_cancelled(cancel_event, "manifest")
                    digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            self._check_cancelled(cancel_event, "manifest")
                            digest.update(chunk)
                    files.append({"name": path.name, "size": path.stat().st_size,
                                  "sha256": digest.hexdigest()})
                offer = {
                    "type": "offer", "version": 1, "transfer_id": transfer_id,
                    "sender": _identity_payload(self.identity), "files": files, "time": int(time.time()),
                }
                offer["signature"] = self.identity.sign(canonical(offer))
                phase = "connect"
                self.callbacks.status(f"Connecting to file server {peer.host}:{peer.port}...")
                connect_error = None
                for attempt in range(1, CONNECT_ATTEMPTS + 1):
                    self._check_cancelled(cancel_event, "connect")
                    try:
                        self.callbacks.status(
                            f"Connecting to file server ({attempt}/{CONNECT_ATTEMPTS})..."
                        )
                        sock = self._connect(
                            peer,
                            trusted["public_key"] if trusted else expected_public_key,
                            timeout=8,
                            local_address=local_address,
                            cancel_event=cancel_event,
                        )
                        break
                    except NetworkError as exc:
                        connect_error = exc
                        if attempt == CONNECT_ATTEMPTS:
                            raise
                        logger.warning(
                            "%s route is not ready; retrying TCP connection in %ss: %s",
                            getattr(getattr(peer, "transport", Transport.WIFI_DIRECT), "value", "route")
                            .replace("_", " ").title(), CONNECT_RETRY_DELAY,
                            exc,
                        )
                        if cancel_event.wait(CONNECT_RETRY_DELAY):
                            raise TransferCancelled("connect")
                if sock is None and connect_error:
                    raise connect_error
                phase = "receiver_approval"
                sock.settimeout(APPROVAL_TIMEOUT)
                self.callbacks.status("File offer sent. Waiting for the receiver to accept (up to 5 minutes)...")
                logger.info("Transfer %s waiting for approval remote=%s:%d", transfer_id, peer.host, peer.port)
                send_control(sock, offer)
                offer_sent = True
                _, decision = recv_frame(sock)
                self._check_cancelled(cancel_event, "receiver_approval")
                if not decision.get("accepted"):
                    raise NetworkError(decision.get("reason", "Transfer declined"))
                if not trusted and expected_public_key:
                    self.store.trust_peer(peer.device_id, peer.display_name, expected_public_key)
                    if self.callbacks.trust_changed:
                        self.callbacks.trust_changed()
                phase = "file_stream"
                sock.settimeout(STREAM_TIMEOUT)
                self.callbacks.status("Accepted. Sending files...")
                total = sum(item["size"] for item in files)
                sent = 0
                tracker = _ProgressTracker(
                    self.callbacks.progress, transfer_id, "send", total, len(files)
                )
                for index, path in enumerate(paths):
                    self._check_cancelled(cancel_event, "file_stream")
                    tracker.update(sent, path.name, index + 1, index, force=True)
                    send_control(sock, {"type": "file_start", "index": index})
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
                            self._check_cancelled(cancel_event, "file_stream")
                            send_chunk(sock, chunk)
                            sent += len(chunk)
                            tracker.update(sent, path.name, index + 1, index)
                    send_control(sock, {"type": "file_end", "index": index})
                    tracker.update(sent, path.name, index + 1, index + 1, force=True)
                send_control(sock, {"type": "transfer_end"})
                phase = "receiver_verification"
                self.callbacks.status("Files sent. Waiting for receiver verification...")
                _, result = recv_frame(sock)
                self._check_cancelled(cancel_event, "receiver_verification")
                if result.get("status") != "complete":
                    raise NetworkError(result.get("reason", "Receiver could not verify the files"))
                self.store.record_transfer(transfer_id, peer.device_id, "sent", {"files": files}, "complete")
                recipient_name = trusted["name"] if trusted else peer.display_name
                self.callbacks.status(f"Sent {len(files)} file(s) to {recipient_name}")
                succeeded = True
            except Exception as exc:
                failure = exc
                if isinstance(exc, TransferCancelled) or cancel_event.is_set():
                    failure = exc if isinstance(exc, TransferCancelled) else TransferCancelled(phase)
                    logger.info("Transfer %s canceled phase=%s", transfer_id, phase)
                    self.callbacks.status("Transfer canceled.")
                else:
                    logger.exception("Transfer %s failed phase=%s remote=%s:%d", transfer_id, phase, peer.host, peer.port)
                    self.callbacks.status(f"Transfer failed during {phase}: {exc}")
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
                self._send_lock.release()
                self._clear_transfer_state("send", cancel_event)
                transport = getattr(peer, "transport", None) or Transport.LAN
                if not isinstance(failure, TransferCancelled):
                    self.store.record_route(peer.device_id, transport.value,
                                            f"{peer.host}:{peer.port}",
                                            time.monotonic() - route_started, succeeded)
                if self.callbacks.result_finished:
                    phase_value = next((value for value in TransferPhase if value.value == phase), TransferPhase.CONNECT)
                    retryable = isinstance(failure, NetworkError) and getattr(failure, "retryable", False)
                    self.callbacks.result_finished(TransferResult(
                        succeeded, TransferPhase.COMPLETE if succeeded else phase_value,
                        retryable, offer_sent, "" if succeeded else str(failure),
                        transport=transport,
                        cancelled=isinstance(failure, TransferCancelled),
                    ))
                self.callbacks.transfer_finished(succeeded)
        threading.Thread(target=work, daemon=True).start()

    def _receive_files(self, sock, offer: dict,
                       cancel_event: threading.Event | None = None) -> ReceiveCompletion | None:
        cancel_event = cancel_event or threading.Event()
        self._check_cancelled(cancel_event, "offer")
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
        if trusted and trusted.get("advertised_name") != sender_name:
            self.store.update_peer_name(device_id, sender_name)
            trusted = self.store.peer(device_id)
        if abs(int(time.time()) - int(offer.get("time", 0))) > 300:
            raise NetworkError("Stale transfer offer")
        try:
            uuid.UUID(hex=offer.get("transfer_id", ""))
        except (ValueError, TypeError):
            raise NetworkError("Invalid transfer identifier")
        offer["files"] = validate_manifest(offer.get("files"))
        if self.callbacks.receive_started:
            self.callbacks.receive_started()
        offered_by = trusted or {
            "device_id": device_id,
            "name": sender_name,
            "public_key": sender_public_key,
            "blocked": False,
        }
        logger.info("Incoming offer transfer=%s sender=%s files=%d", offer["transfer_id"], sender_name, len(offer["files"]))
        folder = (TransferApproval(str(_automatic_destination(sender_name)))
                  if trusted and trusted.get("auto_accept")
                  else self.callbacks.accept_transfer(offered_by, offer["files"]))
        if not folder:
            send_control(sock, {"type": "decision", "accepted": False, "reason": "Transfer declined"})
            return None
        self._check_cancelled(cancel_event, "receiver_approval")
        approval = folder if isinstance(folder, TransferApproval) else TransferApproval(str(folder))
        destination_dir = Path(approval.destination)
        destination_dir.mkdir(parents=True, exist_ok=True)
        if not trusted:
            self.store.trust_peer(device_id, sender_name, sender_public_key,
                                  auto_accept=approval.always_accept)
            trusted = self.store.peer(device_id)
            if self.callbacks.trust_changed:
                self.callbacks.trust_changed()
        elif approval.always_accept:
            self.store.set_auto_accept(device_id, True)
            if self.callbacks.trust_changed:
                self.callbacks.trust_changed()
        required = sum(int(item["size"]) for item in offer["files"])
        if required > __import__("shutil").disk_usage(destination_dir).free:
            send_control(sock, {"type": "decision", "accepted": False, "reason": "Insufficient disk space"})
            return
        sock.settimeout(STREAM_TIMEOUT)
        self.callbacks.status("Receiving files into Downloads...")
        send_control(sock, {"type": "decision", "accepted": True})
        total = required
        received = 0
        completed = []
        tracker = _ProgressTracker(
            self.callbacks.progress, offer["transfer_id"], "receive", total,
            len(offer["files"]),
        )
        for expected_index, manifest in enumerate(offer["files"]):
            self._check_cancelled(cancel_event, "file_stream")
            kind, start = recv_frame(sock)
            if kind != "json" or start != {"index": expected_index, "type": "file_start"}:
                raise NetworkError("Invalid file sequence")
            destination = unique_destination(destination_dir, manifest["name"])
            partial = destination.with_suffix(destination.suffix + ".part")
            digest = hashlib.sha256()
            count = 0
            tracker.update(received, manifest["name"], expected_index + 1,
                           len(completed), force=True)
            try:
                with partial.open("xb") as output:
                    while count < manifest["size"]:
                        self._check_cancelled(cancel_event, "file_stream")
                        kind, chunk = recv_frame(sock)
                        self._check_cancelled(cancel_event, "file_stream")
                        if kind != "chunk" or count + len(chunk) > manifest["size"]:
                            raise NetworkError("Invalid file chunk")
                        output.write(chunk)
                        digest.update(chunk)
                        count += len(chunk)
                        received += len(chunk)
                        tracker.update(received, manifest["name"], expected_index + 1,
                                       len(completed))
                self._check_cancelled(cancel_event, "file_stream")
                kind, end = recv_frame(sock)
                if kind != "json" or end != {"index": expected_index, "type": "file_end"}:
                    raise NetworkError("Missing file terminator")
                if digest.hexdigest() != manifest["sha256"]:
                    raise NetworkError("File integrity verification failed")
                partial.replace(destination)
                completed.append(str(destination))
                tracker.update(received, manifest["name"], expected_index + 1,
                               len(completed), force=True)
            except Exception:
                partial.unlink(missing_ok=True)
                raise
        self._check_cancelled(cancel_event, "file_stream")
        _, end = recv_frame(sock)
        if end.get("type") != "transfer_end":
            raise NetworkError("Missing transfer terminator")
        send_control(sock, {"type": "result", "status": "complete"})
        self.store.record_transfer(offer["transfer_id"], sender["device_id"], "received", {"files": offer["files"]}, "complete")
        self.callbacks.status(f"Received {len(completed)} file(s) from {sender_name}")
        return ReceiveCompletion(sender_name, len(completed), total, str(destination_dir))

    def close(self) -> None:
        self.running = False
        self.cancel_active_transfer()
        with self._link_condition:
            self._links.clear()
            self._link_condition.notify_all()
        self.listener.close()


def _automatic_destination(device_name: str) -> Path:
    safe = "".join(character if character.isalnum() or character in " .-_" else "_"
                   for character in device_name).strip(" .")[:80] or "Unknown device"
    return Path.home() / "Downloads" / "Local Secure Share" / safe
