from __future__ import annotations

import hashlib
import json
import os
import re
import struct
from pathlib import Path

MAX_CONTROL = 1024 * 1024
CHUNK_SIZE = 64 * 1024
CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
# DNS-SD service labels are limited to 15 bytes (RFC 6335).
SERVICE_TYPE = "_lss-share._tcp.local."


def pairing_code() -> str:
    return "".join(CODE_ALPHABET[b % len(CODE_ALPHABET)] for b in os.urandom(8))


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def send_control(sock, value: dict) -> None:
    payload = canonical(value)
    if len(payload) > MAX_CONTROL:
        raise ValueError("control message is too large")
    sock.sendall(b"J" + struct.pack("!I", len(payload)) + payload)


def send_chunk(sock, payload: bytes) -> None:
    sock.sendall(b"B" + struct.pack("!I", len(payload)) + payload)


def _read_exact(sock, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise ConnectionError("peer disconnected")
        data.extend(part)
    return bytes(data)


def recv_frame(sock) -> tuple[str, object]:
    kind = _read_exact(sock, 1)
    length = struct.unpack("!I", _read_exact(sock, 4))[0]
    if length > MAX_CONTROL and kind == b"J":
        raise ValueError("control message is too large")
    if length > CHUNK_SIZE and kind == b"B":
        raise ValueError("file chunk is too large")
    payload = _read_exact(sock, length)
    return ("json", json.loads(payload)) if kind == b"J" else ("chunk", payload)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_filename(value: str) -> str:
    name = Path(value).name
    name = re.sub(r"[\x00-\x1f<>:\"/\\|?*]", "_", name).strip(" .")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if not name or name.upper().split(".")[0] in reserved:
        name = "received_file"
    return name[:240]


def unique_destination(folder: Path, filename: str) -> Path:
    target = folder / safe_filename(filename)
    stem, suffix = target.stem, target.suffix
    number = 1
    while target.exists() or target.with_suffix(target.suffix + ".part").exists():
        target = folder / f"{stem} ({number}){suffix}"
        number += 1
    return target


def validate_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not 1 <= len(files) <= 100:
        raise ValueError("a transfer must contain between 1 and 100 files")
    validated = []
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("invalid file manifest")
        name, size, digest = item.get("name"), item.get("size"), item.get("sha256")
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 1024:
            raise ValueError("invalid filename")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= 2**63 - 1:
            raise ValueError("invalid file size")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid file hash")
        validated.append({"name": name, "size": size, "sha256": digest})
    return validated
