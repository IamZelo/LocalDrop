from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from spake2 import SPAKE2_A, SPAKE2_B

from .discovery import DiscoveredPeer
from .identity import Identity, b64, export_private_key_pem, unb64, verify
from .protocol import CHUNK_SIZE, canonical, hash_file, recv_frame, send_chunk, send_control, unique_destination, validate_manifest
from .storage import LocalStore


class NetworkError(Exception):
    pass


class InteractionCallbacks:
    def __init__(
        self,
        show_pairing_code: Callable[[str, str], bool],
        request_pairing_code: Callable[[str], str | None],
        accept_transfer: Callable[[dict, list[dict]], str | None],
        status: Callable[[str], None],
        progress: Callable[[str, int], None],
        paired: Callable[[], None],
        pairing_finished: Callable[[], None],
        transfer_finished: Callable[[bool], None],
    ):
        self.show_pairing_code = show_pairing_code
        self.request_pairing_code = request_pairing_code
        self.accept_transfer = accept_transfer
        self.status = status
        self.progress = progress
        self.paired = paired
        self.pairing_finished = pairing_finished
        self.transfer_finished = transfer_finished


def _local_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])
    return ip.is_private or ip.is_link_local or ip.is_loopback


def _identity_payload(identity: Identity) -> dict:
    return {"device_id": identity.device_id, "name": identity.display_name, "public_key": identity.public_b64}


def _mac(key: bytes, role: bytes, identity: dict) -> str:
    return b64(hmac.new(key, role + canonical(identity), hashlib.sha256).digest())


class NetworkManager:
    def __init__(self, identity: Identity, store: LocalStore, callbacks: InteractionCallbacks):
        self.identity = identity
        self.store = store
        self.callbacks = callbacks
        self.running = True
        self._pair_attempts: dict[str, deque[float]] = defaultdict(deque)
        self._outgoing_pair_lock = threading.Lock()
        self._incoming_pair_lock = threading.Lock()
        self._server_context = self._make_server_context()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("0.0.0.0", 0))
        self.listener.listen(16)
        self.listener.settimeout(1)
        self.port = self.listener.getsockname()[1]
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

    def _connect(self, peer: DiscoveredPeer, expected_public_key: str | None = None, timeout: float = 20):
        if not _local_address(peer.host):
            raise NetworkError("Refusing an address that is not local or link-local")
        raw = socket.socket(socket.AF_INET6 if ":" in peer.host else socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        wrapped = context.wrap_socket(raw, server_hostname=None)
        wrapped.connect((peer.host, peer.port))
        if expected_public_key:
            cert = x509.load_der_x509_certificate(wrapped.getpeercert(binary_form=True))
            raw_key = cert.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if raw_key != unb64(expected_public_key):
                wrapped.close()
                raise NetworkError("The remote device identity changed. Forget and pair it again if intentional.")
        return wrapped

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
        if not _local_address(address[0]):
            raw.close()
            return
        try:
            sock = self._server_context.wrap_socket(raw, server_side=True)
            sock.settimeout(330)
            kind, first = recv_frame(sock)
            if kind != "json":
                raise NetworkError("Expected a control message")
            if first.get("type") == "pair_begin":
                if not self._incoming_pair_lock.acquire(blocking=False):
                    send_control(sock, {"type": "pair_ready", "accepted": False, "reason": "Another pairing request is already open"})
                else:
                    try:
                        self._receive_pair(sock, address[0], first)
                    finally:
                        self._incoming_pair_lock.release()
            elif first.get("type") == "offer":
                self._receive_files(sock, first)
            else:
                raise NetworkError("Unknown request")
        except Exception as exc:
            self.callbacks.status(f"Incoming connection failed: {exc}")
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def pair(self, peer: DiscoveredPeer) -> bool:
        if not self._outgoing_pair_lock.acquire(blocking=False):
            self.callbacks.status("A pairing attempt is already in progress")
            return False

        def work():
            sock = None
            try:
                self.callbacks.status(f"Connecting to {peer.display_name} for pairing…")
                sock = self._connect(peer, timeout=7)
                send_control(sock, {"type": "pair_begin", "version": 1})
                _, ready = recv_frame(sock)
                if not ready.get("accepted"):
                    raise NetworkError(ready.get("reason", "Pairing declined"))
                code = self.callbacks.request_pairing_code(peer.display_name)
                if not code:
                    send_control(sock, {"type": "cancel"})
                    return
                spake = SPAKE2_A(code.upper().replace("-", "").encode(), idA=b"initiator", idB=b"receiver")
                send_control(sock, {"type": "spake", "message": b64(spake.start())})
                _, response = recv_frame(sock)
                key = spake.finish(unb64(response["message"]))
                mine = _identity_payload(self.identity)
                send_control(sock, {"type": "identity", "identity": mine, "mac": _mac(key, b"initiator", mine)})
                _, remote = recv_frame(sock)
                theirs = remote["identity"]
                if not hmac.compare_digest(remote["mac"], _mac(key, b"receiver", theirs)):
                    raise NetworkError("Pairing confirmation failed")
                self.store.trust_peer(theirs["device_id"], theirs["name"], theirs["public_key"])
                self.callbacks.status(f"Paired with {theirs['name']}")
                self.callbacks.paired()
            except Exception as exc:
                self.callbacks.status(f"Pairing failed: {exc}")
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
                self._outgoing_pair_lock.release()
                self.callbacks.pairing_finished()
        threading.Thread(target=work, daemon=True).start()
        return True

    def _receive_pair(self, sock, address: str, first: dict) -> None:
        from .protocol import pairing_code

        now = time.monotonic()
        attempts = self._pair_attempts[address]
        while attempts and attempts[0] < now - 300:
            attempts.popleft()
        if len(attempts) >= 5:
            send_control(sock, {"type": "pair_ready", "accepted": False, "reason": "Too many pairing attempts; wait five minutes"})
            return
        attempts.append(now)
        code = pairing_code()
        if not self.callbacks.show_pairing_code(address, code):
            send_control(sock, {"type": "pair_ready", "accepted": False, "reason": "Pairing declined"})
            return
        send_control(sock, {"type": "pair_ready", "accepted": True})
        _, incoming = recv_frame(sock)
        if incoming.get("type") == "cancel":
            return
        spake = SPAKE2_B(code.encode(), idA=b"initiator", idB=b"receiver")
        outbound = spake.start()
        key = spake.finish(unb64(incoming["message"]))
        send_control(sock, {"type": "spake", "message": b64(outbound)})
        _, remote = recv_frame(sock)
        theirs = remote["identity"]
        if not hmac.compare_digest(remote["mac"], _mac(key, b"initiator", theirs)):
            raise NetworkError("Pairing confirmation failed")
        mine = _identity_payload(self.identity)
        send_control(sock, {"type": "identity", "identity": mine, "mac": _mac(key, b"receiver", mine)})
        self.store.trust_peer(theirs["device_id"], theirs["name"], theirs["public_key"])
        self.callbacks.status(f"Paired with {theirs['name']}")
        self.callbacks.paired()

    def send_files(self, peer: DiscoveredPeer, paths: list[Path]) -> None:
        trusted = self.store.peer(peer.device_id)
        if not trusted:
            self.callbacks.status("Pair with this device before sending files")
            return

        def work():
            transfer_id = uuid.uuid4().hex
            succeeded = False
            sock = None
            try:
                self.callbacks.status("Preparing file manifest...")
                files = [{"name": p.name, "size": p.stat().st_size, "sha256": hash_file(p)} for p in paths]
                offer = {
                    "type": "offer", "version": 1, "transfer_id": transfer_id,
                    "sender": _identity_payload(self.identity), "files": files, "time": int(time.time()),
                }
                offer["signature"] = self.identity.sign(canonical(offer))
                sock = self._connect(peer, trusted["public_key"])
                send_control(sock, offer)
                _, decision = recv_frame(sock)
                if not decision.get("accepted"):
                    raise NetworkError(decision.get("reason", "Transfer declined"))
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
                _, result = recv_frame(sock)
                if result.get("status") != "complete":
                    raise NetworkError(result.get("reason", "Receiver could not verify the files"))
                self.store.record_transfer(transfer_id, peer.device_id, "sent", {"files": files}, "complete")
                self.callbacks.status(f"Sent {len(files)} file(s) to {trusted['name']}")
                self.callbacks.progress(transfer_id, 100)
                succeeded = True
            except Exception as exc:
                self.callbacks.status(f"Transfer failed: {exc}")
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass
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
        self.listener.close()
