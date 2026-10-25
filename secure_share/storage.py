from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

import keyring
from cryptography.fernet import Fernet

from .identity import SERVICE, app_data_dir


class LocalStore:
    def __init__(self, device_id: str):
        self.path = app_data_dir() / "history.sqlite3"
        self.cipher = Fernet(self._load_key(device_id))
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS peers (
                device_id TEXT PRIMARY KEY, public_key TEXT NOT NULL,
                encrypted_name BLOB NOT NULL, paired_at TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS transfers (
                id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, direction TEXT NOT NULL,
                encrypted_details BLOB NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )
        self.db.commit()

    def _load_key(self, device_id: str) -> bytes:
        account = f"{device_id}:history"
        try:
            value = keyring.get_password(SERVICE, account)
            if value:
                return value.encode("ascii")
            key = Fernet.generate_key()
            keyring.set_password(SERVICE, account, key.decode("ascii"))
            return key
        except Exception:
            path = app_data_dir() / "history.key"
            if path.exists():
                return path.read_bytes()
            key = Fernet.generate_key()
            path.write_bytes(key)
            try:
                path.chmod(0o600)
            except OSError:
                pass
            return key

    def trust_peer(self, device_id: str, name: str, public_key: str) -> None:
        encrypted = self.cipher.encrypt(name.encode())
        with self.lock:
            self.db.execute(
                "INSERT INTO peers(device_id,public_key,encrypted_name,paired_at,blocked) VALUES(?,?,?,?,0) "
                "ON CONFLICT(device_id) DO UPDATE SET public_key=excluded.public_key, encrypted_name=excluded.encrypted_name, blocked=0",
                (device_id, public_key, encrypted, datetime.now(timezone.utc).isoformat()),
            )
            self.db.commit()

    def peer(self, device_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute(
                "SELECT device_id,public_key,encrypted_name,blocked FROM peers WHERE device_id=?", (device_id,)
            ).fetchone()
        if not row:
            return None
        return {"device_id": row[0], "public_key": row[1], "name": self.cipher.decrypt(row[2]).decode(), "blocked": bool(row[3])}

    def peers(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT device_id FROM peers WHERE blocked=0").fetchall()
        return [peer for (device_id,) in rows if (peer := self.peer(device_id))]

    def forget_peer(self, device_id: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM peers WHERE device_id=?", (device_id,))
            self.db.execute("DELETE FROM transfers WHERE peer_id=?", (device_id,))
            self.db.commit()

    def record_transfer(self, transfer_id: str, peer_id: str, direction: str, details: dict, status: str) -> None:
        encrypted = self.cipher.encrypt(json.dumps(details).encode())
        with self.lock:
            self.db.execute(
                "INSERT OR REPLACE INTO transfers VALUES(?,?,?,?,?,?)",
                (transfer_id, peer_id, direction, encrypted, status, datetime.now(timezone.utc).isoformat()),
            )
            self.db.commit()

    def recents(self, limit: int = 10) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                """SELECT peer_id, MAX(created_at) last_seen, COUNT(*) count
                   FROM transfers WHERE status='complete' GROUP BY peer_id
                   ORDER BY last_seen DESC, count DESC LIMIT ?""", (limit,)
            ).fetchall()
        result = []
        for peer_id, last_seen, count in rows:
            peer = self.peer(peer_id)
            if peer:
                result.append({**peer, "last_seen": last_seen, "count": count})
        return result

    def close(self) -> None:
        with self.lock:
            self.db.close()
