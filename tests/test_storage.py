import sqlite3
import threading
import unittest

from cryptography.fernet import Fernet

from secure_share.storage import LocalStore


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.store = object.__new__(LocalStore)
        self.store.cipher = Fernet(Fernet.generate_key())
        self.store.lock = threading.RLock()
        self.store.db = sqlite3.connect(":memory:")
        self.store.db.execute("""CREATE TABLE peers (
            device_id TEXT PRIMARY KEY, public_key TEXT NOT NULL,
            encrypted_name BLOB NOT NULL, paired_at TEXT NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0,
            capabilities TEXT NOT NULL DEFAULT 'lan', last_seen TEXT,
            auto_accept INTEGER NOT NULL DEFAULT 0, encrypted_alias BLOB
        )""")

    def tearDown(self):
        self.store.db.close()

    def test_trusted_device_alias_can_be_set_and_cleared(self):
        self.store.trust_peer("peer", "Office Laptop", "public-key")
        self.store.rename_peer("peer", "Harsh's PC")
        renamed = self.store.peer("peer")
        self.assertEqual(renamed["name"], "Harsh's PC")
        self.assertEqual(renamed["advertised_name"], "Office Laptop")
        self.assertEqual(renamed["alias"], "Harsh's PC")
        raw_alias = self.store.db.execute(
            "SELECT encrypted_alias FROM peers WHERE device_id='peer'"
        ).fetchone()[0]
        self.assertNotIn(b"Harsh", raw_alias)

        self.store.trust_peer("peer", "Office Laptop Renamed", "public-key")
        self.assertEqual(self.store.peer("peer")["name"], "Harsh's PC")

        self.store.rename_peer("peer", "  ")
        restored = self.store.peer("peer")
        self.assertEqual(restored["name"], "Office Laptop Renamed")
        self.assertIsNone(restored["alias"])

    def test_rename_unknown_device_is_rejected(self):
        with self.assertRaises(KeyError):
            self.store.rename_peer("missing", "Alias")

    def test_migration_adds_alias_to_existing_peer_table(self):
        legacy = object.__new__(LocalStore)
        legacy.db = sqlite3.connect(":memory:")
        try:
            legacy.db.execute("""CREATE TABLE peers (
                device_id TEXT PRIMARY KEY, public_key TEXT NOT NULL,
                encrypted_name BLOB NOT NULL, paired_at TEXT NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0
            )""")
            legacy._migrate()
            columns = {row[1] for row in legacy.db.execute("PRAGMA table_info(peers)")}
            self.assertIn("encrypted_alias", columns)
        finally:
            legacy.db.close()


if __name__ == "__main__":
    unittest.main()
