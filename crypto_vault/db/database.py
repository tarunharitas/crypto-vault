"""SQLite persistence using parameterized SQL throughout."""
from __future__ import annotations

import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS credentials (
 id INTEGER PRIMARY KEY, service TEXT NOT NULL, username TEXT NOT NULL,
 nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
 aad_version INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(service, username));
"""

class Database:
    def __init__(self, path: Path):
        self.path = Path(path).expanduser()
        if self.path.is_symlink():
            raise ValueError("Database path must not be a symbolic link")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        if os.name not in {"nt"}:
            os.chmod(self.path, 0o600)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(credentials)")}
        if "aad_version" not in columns:
            self.conn.execute("ALTER TABLE credentials ADD COLUMN aad_version INTEGER NOT NULL DEFAULT 1")
            self.conn.commit()

    def close(self): self.conn.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def get_meta(self, key: str) -> bytes | None:
        row = self.conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return bytes(row[0]) if row else None

    def set_meta(self, key: str, value: bytes) -> None:
        with self.transaction():
            self.conn.execute("INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def set_meta_many(self, values: dict[str, bytes]) -> None:
        with self.transaction():
            self.conn.executemany("INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", values.items())

    def upsert_credential(self, service: str, username: str, nonce: bytes, ciphertext: bytes, aad_version: int = 2) -> None:
        with self.transaction():
            self.conn.execute("""INSERT INTO credentials(service,username,nonce,ciphertext,aad_version) VALUES(?,?,?,?,?)
              ON CONFLICT(service,username) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,aad_version=excluded.aad_version,updated_at=CURRENT_TIMESTAMP""",
              (service, username, nonce, ciphertext, aad_version))

    def get_credential(self, service: str, username: str | None = None):
        if username is None:
            rows = self.conn.execute("SELECT * FROM credentials WHERE service=? ORDER BY username", (service,)).fetchall()
            if len(rows) > 1: raise ValueError("Multiple usernames found; provide --username")
            return rows[0] if rows else None
        return self.conn.execute("SELECT * FROM credentials WHERE service=? AND username=?", (service, username)).fetchone()

    def list_credentials(self):
        return self.conn.execute("SELECT service,username,created_at,updated_at FROM credentials ORDER BY service,username").fetchall()

    def delete_credential(self, service: str, username: str | None = None) -> int:
        if username is None:
            cur = self.conn.execute("DELETE FROM credentials WHERE service=?", (service,))
        else:
            cur = self.conn.execute("DELETE FROM credentials WHERE service=? AND username=?", (service, username))
        self.conn.commit(); return cur.rowcount
