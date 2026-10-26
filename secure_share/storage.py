from __future__ import annotations

import json
import sqlite3
import threading
import time
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
        self._migrate()
        self.db.commit()

    def _migrate(self) -> None:
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(peers)")}
        additions = {
            "capabilities": "TEXT NOT NULL DEFAULT 'lan'",
            "last_seen": "TEXT",
            "auto_accept": "INTEGER NOT NULL DEFAULT 0",
            "encrypted_alias": "BLOB",
        }
        for name, declaration in additions.items():
            if name not in columns:
                self.db.execute(f"ALTER TABLE peers ADD COLUMN {name} {declaration}")
        self.db.execute("""CREATE TABLE IF NOT EXISTS route_stats (
            device_id TEXT NOT NULL, transport TEXT NOT NULL, endpoint TEXT NOT NULL,
            successes INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
            consecutive_failures INTEGER NOT NULL DEFAULT 0, latency_total REAL NOT NULL DEFAULT 0,
            last_attempt TEXT NOT NULL, cooldown_until REAL NOT NULL DEFAULT 0,
            PRIMARY KEY(device_id, transport, endpoint)
        )""")

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

    def trust_peer(self, device_id: str, name: str, public_key: str, *,
                   capabilities: str = "lan", auto_accept: bool = False) -> None:
        encrypted = self.cipher.encrypt(name.encode())
        with self.lock:
            self.db.execute(
                "INSERT INTO peers(device_id,public_key,encrypted_name,paired_at,blocked,capabilities,last_seen,auto_accept) VALUES(?,?,?,?,0,?,?,?) "
                "ON CONFLICT(device_id) DO UPDATE SET public_key=excluded.public_key, encrypted_name=excluded.encrypted_name, blocked=0, capabilities=?, last_seen=?, auto_accept=?",
                (device_id, public_key, encrypted, datetime.now(timezone.utc).isoformat(), capabilities,
                 datetime.now(timezone.utc).isoformat(), int(auto_accept), capabilities,
                 datetime.now(timezone.utc).isoformat(), int(auto_accept)),
            )
            self.db.commit()

    def peer(self, device_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute(
                "SELECT device_id,public_key,encrypted_name,blocked,capabilities,last_seen,auto_accept,encrypted_alias FROM peers WHERE device_id=?", (device_id,)
            ).fetchone()
        if not row:
            return None
        advertised_name = self.cipher.decrypt(row[2]).decode()
        alias = self.cipher.decrypt(row[7]).decode() if row[7] else None
        return {"device_id": row[0], "public_key": row[1], "name": alias or advertised_name,
                "advertised_name": advertised_name, "alias": alias,
                "blocked": bool(row[3]), "capabilities": row[4] or "lan", "last_seen": row[5],
                "auto_accept": bool(row[6])}

    def rename_peer(self, device_id: str, alias: str | None) -> None:
        """Set a private display alias; an empty value restores the advertised name."""
        normalized = (alias or "").strip()
        encrypted = self.cipher.encrypt(normalized.encode()) if normalized else None
        with self.lock:
            cursor = self.db.execute(
                "UPDATE peers SET encrypted_alias=? WHERE device_id=?", (encrypted, device_id)
            )
            if cursor.rowcount != 1:
                raise KeyError(f"Unknown trusted device: {device_id}")
            self.db.commit()

    def update_peer_name(self, device_id: str, advertised_name: str) -> None:
        """Refresh a verified peer name while preserving its private alias."""
        encrypted = self.cipher.encrypt(advertised_name.encode())
        with self.lock:
            self.db.execute(
                "UPDATE peers SET encrypted_name=? WHERE device_id=?", (encrypted, device_id)
            )
            self.db.commit()

    def observe_peer(self, device_id: str, capabilities: str) -> None:
        with self.lock:
            self.db.execute("UPDATE peers SET capabilities=?, last_seen=? WHERE device_id=?",
                            (capabilities, datetime.now(timezone.utc).isoformat(), device_id))
            self.db.commit()

    def set_auto_accept(self, device_id: str, enabled: bool) -> None:
        with self.lock:
            self.db.execute("UPDATE peers SET auto_accept=? WHERE device_id=?", (int(enabled), device_id))
            self.db.commit()

    def set_blocked(self, device_id: str, blocked: bool) -> None:
        with self.lock:
            self.db.execute("UPDATE peers SET blocked=?, auto_accept=CASE WHEN ? THEN 0 ELSE auto_accept END WHERE device_id=?",
                            (int(blocked), int(blocked), device_id))
            self.db.commit()

    def record_route(self, device_id: str, transport: str, endpoint: str, duration: float,
                     succeeded: bool) -> None:
        now = datetime.now(timezone.utc).isoformat()
        cooldown = 0.0 if succeeded else time.time() + 30
        with self.lock:
            self.db.execute("""INSERT INTO route_stats VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(device_id,transport,endpoint) DO UPDATE SET
                successes=successes+excluded.successes, failures=failures+excluded.failures,
                consecutive_failures=CASE WHEN excluded.successes=1 THEN 0 ELSE consecutive_failures+1 END,
                latency_total=latency_total+excluded.latency_total,last_attempt=excluded.last_attempt,
                cooldown_until=excluded.cooldown_until""",
                (device_id, transport, endpoint, int(succeeded), int(not succeeded),
                 0 if succeeded else 1, duration if succeeded else 0, now, cooldown))
            self.db.commit()

    def route_stats(self, device_id: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT transport,endpoint,successes,failures,consecutive_failures,latency_total,cooldown_until FROM route_stats WHERE device_id=?", (device_id,)).fetchall()
        return [{"transport": r[0], "endpoint": r[1], "successes": r[2], "failures": r[3],
                 "consecutive_failures": r[4], "average_latency": r[5] / r[2] if r[2] else None,
                 "cooldown_until": r[6]} for r in rows]

    def rank_endpoints(self, device_id: str, endpoints: list[str], now: float | None = None) -> list[str]:
        """Prefer proven endpoints and leave recently failed ones until last."""
        current = time.time() if now is None else now
        stats = {row["endpoint"]: row for row in self.route_stats(device_id)}
        def score(endpoint: str) -> tuple[bool, float, int, float]:
            row = stats.get(endpoint, {})
            cooled = float(row.get("cooldown_until", 0)) > current
            attempts = int(row.get("successes", 0)) + int(row.get("failures", 0))
            reliability = int(row.get("successes", 0)) / attempts if attempts else 0.5
            latency = row.get("average_latency")
            return cooled, -reliability, int(row.get("consecutive_failures", 0)), latency or float("inf")
        return sorted(endpoints, key=score)

    def peers(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT device_id FROM peers WHERE blocked=0").fetchall()
        return [peer for (device_id,) in rows if (peer := self.peer(device_id))]

    def forget_peer(self, device_id: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM peers WHERE device_id=?", (device_id,))
            self.db.execute("DELETE FROM transfers WHERE peer_id=?", (device_id,))
            self.db.execute("DELETE FROM route_stats WHERE device_id=?", (device_id,))
            self.db.commit()

    def revoke_trust(self, device_id: str) -> None:
        """Remove identity pinning and auto-accept without erasing history or route learning."""
        with self.lock:
            self.db.execute("DELETE FROM peers WHERE device_id=?", (device_id,))
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
