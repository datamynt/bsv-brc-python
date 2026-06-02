"""Storage for an overlay node's topical UTXO set.

The :class:`OverlayEngine` tracks which outputs each topic has admitted
so it can (a) tell topic managers which inputs of a new transaction are
previously-admitted coins, and (b) detect when those coins are spent.
This is deliberately a small interface: lookup services keep their own
indexes (built from admit/spend events), so storage only holds the
topical UTXO set plus the BEEF needed to reconstruct admitted outputs.

The in-memory reference is fine for development and small nodes; for
production back it with SQLite/Postgres by implementing
:class:`OverlayStorage`.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from typing import Iterator, Optional, Protocol, runtime_checkable

__all__ = [
    "StoredOutput",
    "OverlayStorage",
    "InMemoryOverlayStorage",
    "SqliteOverlayStorage",
]


@dataclass
class StoredOutput:
    """An output admitted to a topic."""

    topic: str
    txid: str
    output_index: int
    locking_script: bytes
    satoshis: int
    spent: bool = False


@runtime_checkable
class OverlayStorage(Protocol):
    """The persistence surface the overlay engine needs."""

    def insert_output(
        self,
        topic: str,
        txid: str,
        output_index: int,
        locking_script: bytes,
        satoshis: int,
    ) -> None:
        ...

    def mark_spent(self, topic: str, txid: str, output_index: int) -> None:
        ...

    def is_unspent(self, topic: str, txid: str, output_index: int) -> bool:
        ...

    def put_beef(self, txid: str, beef: bytes) -> None:
        ...

    def get_beef(self, txid: str) -> Optional[bytes]:
        ...

    def outputs(self, topic: Optional[str] = None) -> Iterator[StoredOutput]:
        ...


class InMemoryOverlayStorage:
    """Dict-backed :class:`OverlayStorage` for development and tests."""

    def __init__(self) -> None:
        self._outputs: dict[tuple[str, str, int], StoredOutput] = {}
        self._beef: dict[str, bytes] = {}

    def insert_output(
        self,
        topic: str,
        txid: str,
        output_index: int,
        locking_script: bytes,
        satoshis: int,
    ) -> None:
        key = (topic, txid, output_index)
        self._outputs[key] = StoredOutput(
            topic=topic,
            txid=txid,
            output_index=output_index,
            locking_script=locking_script,
            satoshis=satoshis,
        )

    def mark_spent(self, topic: str, txid: str, output_index: int) -> None:
        out = self._outputs.get((topic, txid, output_index))
        if out is not None:
            out.spent = True

    def is_unspent(self, topic: str, txid: str, output_index: int) -> bool:
        out = self._outputs.get((topic, txid, output_index))
        return out is not None and not out.spent

    def put_beef(self, txid: str, beef: bytes) -> None:
        self._beef[txid] = beef

    def get_beef(self, txid: str) -> Optional[bytes]:
        return self._beef.get(txid)

    def outputs(self, topic: Optional[str] = None) -> Iterator[StoredOutput]:
        for out in list(self._outputs.values()):
            if topic is None or out.topic == topic:
                yield out


class SqliteOverlayStorage:
    """A persistent :class:`OverlayStorage` backed by SQLite.

    Suitable for a single-process overlay node. Pass a file path to
    persist across restarts, or ``":memory:"`` for an ephemeral store.
    A lock serializes writes so the store is safe to share across the
    threads a typical ASGI server uses.

    Example::

        storage = SqliteOverlayStorage("overlay.db")
        engine = OverlayEngine(managers, services, storage=storage)
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS outputs (
                    topic         TEXT NOT NULL,
                    txid          TEXT NOT NULL,
                    output_index  INTEGER NOT NULL,
                    locking_script BLOB NOT NULL,
                    satoshis      INTEGER NOT NULL,
                    spent         INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (topic, txid, output_index)
                );
                CREATE TABLE IF NOT EXISTS beef (
                    txid TEXT PRIMARY KEY,
                    beef BLOB NOT NULL
                );
                """
            )
            self._conn.commit()

    def insert_output(
        self,
        topic: str,
        txid: str,
        output_index: int,
        locking_script: bytes,
        satoshis: int,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO outputs "
                "(topic, txid, output_index, locking_script, satoshis, spent) "
                "VALUES (?, ?, ?, ?, ?, 0)",
                (topic, txid, output_index, locking_script, satoshis),
            )
            self._conn.commit()

    def mark_spent(self, topic: str, txid: str, output_index: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE outputs SET spent = 1 "
                "WHERE topic = ? AND txid = ? AND output_index = ?",
                (topic, txid, output_index),
            )
            self._conn.commit()

    def is_unspent(self, topic: str, txid: str, output_index: int) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT spent FROM outputs "
                "WHERE topic = ? AND txid = ? AND output_index = ?",
                (topic, txid, output_index),
            )
            row = cur.fetchone()
        return row is not None and row[0] == 0

    def put_beef(self, txid: str, beef: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO beef (txid, beef) VALUES (?, ?)",
                (txid, beef),
            )
            self._conn.commit()

    def get_beef(self, txid: str) -> Optional[bytes]:
        with self._lock:
            cur = self._conn.execute("SELECT beef FROM beef WHERE txid = ?", (txid,))
            row = cur.fetchone()
        return bytes(row[0]) if row is not None else None

    def outputs(self, topic: Optional[str] = None) -> Iterator[StoredOutput]:
        # Materialize fully under the lock; the shared connection is not
        # safe to step from another thread mid-iteration, and holding the
        # lock across a consumer's loop could deadlock with writers.
        with self._lock:
            if topic is None:
                cur = self._conn.execute(
                    "SELECT topic, txid, output_index, locking_script, satoshis, spent "
                    "FROM outputs"
                )
            else:
                cur = self._conn.execute(
                    "SELECT topic, txid, output_index, locking_script, satoshis, spent "
                    "FROM outputs WHERE topic = ?",
                    (topic,),
                )
            rows = cur.fetchall()
        for row in rows:
            yield StoredOutput(
                topic=row[0],
                txid=row[1],
                output_index=row[2],
                locking_script=bytes(row[3]),
                satoshis=row[4],
                spent=bool(row[5]),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
