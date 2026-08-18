"""
BRC-138 single-use nonce stores.

A single-use store answers "was this nonce already used?" and MUST do so
atomically — a single conditional write (e.g. a uniqueness constraint), never
a read-then-write, otherwise two concurrent requests bearing the same nonce
can both be accepted. Entries only need to be retained until the proof's
``expires_at``; because expiry is enforced independently by the freshness
check, an entry whose ``expires_at`` has passed can be evicted safely, so
storage stays bounded to proofs seen within one validity window.

- :class:`MemorySingleUseStore` — a locked in-memory map, acceptable for a
  single long-lived process.
- :class:`SqliteSingleUseStore` — backed by a SQLite table with a PRIMARY KEY
  unique index; usable in multi-process deployments on a shared database file.
  In serverless / multi-instance deployments use a shared database with a
  unique index (any DB; the SQL here is deliberately portable).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from typing import Optional


class SingleUseStore(ABC):
    """Atomic insert-if-not-exists store for consumed proof nonces."""

    @abstractmethod
    def insert_if_not_exists(self, nonce: str, expires_at: Optional[int] = None) -> bool:
        """
        Atomically record ``nonce`` as used.

        Returns True if this call consumed it (it was not already present),
        False if it was already recorded (a replay). ``expires_at`` is the
        proof's expiry in epoch ms, used for bounded retention.
        """

    @abstractmethod
    def evict_expired(self, now_ms: Optional[int] = None) -> int:
        """Drop entries whose expiry has passed; return the count removed."""


class MemorySingleUseStore(SingleUseStore):
    """In-memory single-use store with lazy expiry eviction.

    Safe for a single long-lived process. ``insert_if_not_exists`` prunes
    expired entries opportunistically and is atomic under a lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}  # nonce -> expires_at (epoch ms)

    def insert_if_not_exists(self, nonce: str, expires_at: Optional[int] = None) -> bool:
        now_ms = int(time.time() * 1000)
        with self._lock:
            self._prune_locked(now_ms)
            if nonce in self._seen:
                return False
            self._seen[nonce] = expires_at if expires_at is not None else now_ms
            return True

    def evict_expired(self, now_ms: Optional[int] = None) -> int:
        with self._lock:
            return self._prune_locked(int(time.time() * 1000) if now_ms is None else now_ms)

    def _prune_locked(self, now_ms: int) -> int:
        expired = [n for n, exp in self._seen.items() if exp < now_ms]
        for n in expired:
            del self._seen[n]
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


class SqliteSingleUseStore(SingleUseStore):
    """SQLite-backed single-use store.

    Uses ``INSERT OR IGNORE`` against a PRIMARY KEY unique index — atomic for
    concurrent processes sharing the database file. Set ``check_same_thread``
    appropriately (SQLite defaults to per-connection threading; pass
    ``check_same_thread=False`` if the connection is shared across threads and
    guard with the connection's own locking or a lock here).

    Args:
        path: SQLite database path (``":memory:"`` supported).
        table: Table name for consumed nonces.
    """

    def __init__(
        self,
        path: str = ":memory:",
        table: str = "auth_proof_nonces",
        check_same_thread: bool = True,
    ) -> None:
        self._path = path
        self._table = table
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=check_same_thread)
        self._conn.execute(
            f"CREATE TABLE IF NOT EXISTS {table} ("
            "nonce TEXT PRIMARY KEY, "
            "expires_at INTEGER NOT NULL)"
        )
        self._conn.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{table}_expires ON {table}(expires_at)"
        )
        self._conn.commit()

    def insert_if_not_exists(self, nonce: str, expires_at: Optional[int] = None) -> bool:
        now_ms = int(time.time() * 1000)
        exp = now_ms if expires_at is None else expires_at
        with self._lock:
            # Opportunistic eviction keeps the table bounded.
            self._conn.execute(
                f"DELETE FROM {self._table} WHERE expires_at < ?", (now_ms,)
            )
            cur = self._conn.execute(
                f"INSERT OR IGNORE INTO {self._table} (nonce, expires_at) VALUES (?, ?)",
                (nonce, exp),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def evict_expired(self, now_ms: Optional[int] = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                f"DELETE FROM {self._table} WHERE expires_at < ?",
                (int(time.time() * 1000) if now_ms is None else now_ms,),
            )
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = [
    "MemorySingleUseStore",
    "SingleUseStore",
    "SqliteSingleUseStore",
]
