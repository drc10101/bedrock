"""
SQLite storage backend for Bedrock modules.

Persists module state to a SQLite database with one table per module.
Each module serializes its state as JSON for flexible schema evolution.

Table structure:
  - bedrock_nodes: registered nodes
  - bedrock_certificates: issued certificates
  - bedrock_silos: data silos
  - bedrock_consents: consent events
  - bedrock_audit: audit chain entries
  - bedrock_keys: encryption keys
  - bedrock_licenses: signing keys

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import cast


class SQLiteBackend:
    """SQLite-based persistence backend for Bedrock modules.

    Thread-safe: uses a per-thread connection model with WAL mode
    for concurrent reads.

    Usage:
        storage = SQLiteBackend("bedrock.db")
        storage.save("nodes", "node-123", {"name": "server-1", "type": "provider"})
        node = storage.load("nodes", "node-123")
        nodes = storage.load_all("nodes")
        storage.delete("nodes", "node-123")
    """

    def __init__(self, db_path: str = "bedrock.db", wal_mode: bool = True):
        """Initialize SQLite backend.

        Args:
            db_path: Path to the SQLite database file. Use ":memory:" for
                in-memory databases (single shared connection, no WAL).
            wal_mode: If True, enable WAL mode for concurrent read access.
                Ignored for in-memory databases.
        """
        self.db_path = db_path
        self._in_memory = db_path == ":memory:"
        self._wal_mode = wal_mode and not self._in_memory
        self._shared_conn: sqlite3.Connection | None = None
        self._local = threading.local()
        self._lock = threading.Lock()
        self._initialized_tables: set[str] = set()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a database connection.

        For in-memory databases, returns a single shared connection
        (since :memory: DBs are connection-scoped). For file databases,
        returns a per-thread connection with WAL mode.
        """
        if self._in_memory:
            if self._shared_conn is None:
                self._shared_conn = sqlite3.connect(self.db_path, check_same_thread=False)
                self._shared_conn.execute("PRAGMA synchronous=NORMAL")
                self._shared_conn.execute("PRAGMA foreign_keys=ON")
                self._shared_conn.row_factory = sqlite3.Row
            return self._shared_conn

        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return cast(sqlite3.Connection, self._local.conn)

    def _ensure_table(self, table: str) -> None:
        """Create the table if it doesn't exist (lazy migration)."""
        if table in self._initialized_tables:
            return
        with self._lock:
            if table in self._initialized_tables:
                return
            conn = self._get_conn()
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    key TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_updated ON {table}(updated_at)")
            conn.commit()
            self._initialized_tables.add(table)

    def save(self, table: str, key: str, data: dict) -> None:
        """Save or update a record.

        Args:
            table: Module table name (e.g., 'nodes', 'silos').
            key: Unique key for the record.
            data: Dictionary to serialize as JSON.
        """
        self._ensure_table(table)
        conn = self._get_conn()
        data_json = json.dumps(data, separators=(",", ":"), sort_keys=True)
        conn.execute(
            f"INSERT OR REPLACE INTO {table} (key, data, updated_at) VALUES (?, ?, ?)",
            (key, data_json, time.time()),
        )
        conn.commit()

    def load(self, table: str, key: str) -> dict | None:
        """Load a record by key.

        Args:
            table: Module table name.
            key: Unique key for the record.

        Returns:
            Dictionary of the record, or None if not found.
        """
        self._ensure_table(table)
        conn = self._get_conn()
        row = conn.execute(f"SELECT data FROM {table} WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return cast(dict, json.loads(row["data"]))

    def load_all(self, table: str) -> dict[str, dict]:
        """Load all records from a table.

        Returns:
            Dictionary mapping keys to data dictionaries.
        """
        self._ensure_table(table)
        conn = self._get_conn()
        rows = conn.execute(f"SELECT key, data FROM {table}").fetchall()
        return {row["key"]: json.loads(row["data"]) for row in rows}

    def delete(self, table: str, key: str) -> bool:
        """Delete a record by key.

        Returns:
            True if a record was deleted, False if not found.
        """
        self._ensure_table(table)
        conn = self._get_conn()
        cursor = conn.execute(f"DELETE FROM {table} WHERE key = ?", (key,))
        conn.commit()
        return cursor.rowcount > 0

    def count(self, table: str) -> int:
        """Count records in a table."""
        self._ensure_table(table)
        conn = self._get_conn()
        row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
        return cast(int, row["cnt"])

    def exists(self, table: str, key: str) -> bool:
        """Check if a record exists."""
        self._ensure_table(table)
        conn = self._get_conn()
        row = conn.execute(f"SELECT 1 FROM {table} WHERE key = ?", (key,)).fetchone()
        return row is not None

    def query(self, table: str, filter_fn: Callable[[dict], bool] | None = None) -> dict[str, dict]:
        """Load records with an optional filter function.

        Args:
            table: Module table name.
            filter_fn: Optional callable(data_dict) -> bool.

        Returns:
            Dictionary mapping keys to data dictionaries.
        """
        self._ensure_table(table)
        conn = self._get_conn()
        rows = conn.execute(f"SELECT key, data FROM {table}").fetchall()
        results = {}
        for row in rows:
            data = json.loads(row["data"])
            if filter_fn is None or filter_fn(data):
                results[row["key"]] = data
        return results

    def clear_table(self, table: str) -> int:
        """Delete all records from a table.

        Returns:
            Number of records deleted.
        """
        self._ensure_table(table)
        conn = self._get_conn()
        cursor = conn.execute(f"DELETE FROM {table}")
        conn.commit()
        return cursor.rowcount

    def list_tables(self) -> list[str]:
        """List all Bedrock tables in the database."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'bedrock_%'"
        ).fetchall()
        return [row["name"] for row in rows]

    def close(self) -> None:
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    def __enter__(self) -> "SQLiteBackend":
        return self

    def __exit__(
        self, exc_type: type | None, exc_val: BaseException | None, exc_tb: object | None
    ) -> None:
        self.close()

    # --- Module-specific convenience methods ---

    def save_node(self, node_data: dict) -> None:
        """Save a registered node."""
        node_id = node_data.get("uuid") or node_data.get("node_id", "")
        self.save("bedrock_nodes", node_id, node_data)

    def load_nodes(self) -> dict[str, dict]:
        """Load all registered nodes."""
        return self.load_all("bedrock_nodes")

    def save_certificate(self, cert_data: dict) -> None:
        """Save an issued certificate."""
        serial = cert_data.get("serial_number", "")
        self.save("bedrock_certificates", serial, cert_data)

    def load_certificates(self) -> dict[str, dict]:
        """Load all issued certificates."""
        return self.load_all("bedrock_certificates")

    def save_silo(self, silo_data: dict) -> None:
        """Save a data silo."""
        silo_id = silo_data.get("silo_id", "")
        self.save("bedrock_silos", silo_id, silo_data)

    def load_silos(self) -> dict[str, dict]:
        """Load all data silos."""
        return self.load_all("bedrock_silos")

    def save_consent(self, consent_data: dict) -> None:
        """Save a consent event."""
        consent_id = consent_data.get("consent_id", "")
        self.save("bedrock_consents", consent_id, consent_data)

    def load_consents(self) -> dict[str, dict]:
        """Load all consent events."""
        return self.load_all("bedrock_consents")

    def save_audit_entry(self, entry_data: dict) -> None:
        """Save an audit chain entry."""
        entry_id = entry_data.get("entry_id", str(entry_data.get("timestamp", "")))
        self.save("bedrock_audit", entry_id, entry_data)

    def load_audit_chain(self) -> dict[str, dict]:
        """Load all audit chain entries."""
        return self.load_all("bedrock_audit")

    def save_signing_key(self, key_data: dict) -> None:
        """Save a license signing key."""
        key_id = key_data.get("key_id", "")
        self.save("bedrock_licenses", key_id, key_data)

    def load_signing_keys(self) -> dict[str, dict]:
        """Load all license signing keys."""
        return self.load_all("bedrock_licenses")

    def save_api_key(self, key_data: dict) -> None:
        """Save a registered API key."""
        api_key = key_data.get("key", "")
        self.save("bedrock_api_keys", api_key, key_data)

    def load_api_keys(self) -> dict[str, dict]:
        """Load all registered API keys."""
        return self.load_all("bedrock_api_keys")
