"""
Run an overlay node in Python.

py-sdk gives you the overlay *client* (broadcast and resolve); this
package is the *server* — the thing that admits transactions to topics,
indexes them through lookup services, and answers queries. It is the
keystone for building a social app (or any app) on overlay: the part
that turns a stream of submitted transactions into a queryable feed.

- :class:`OverlayEngine` — composes BRC-22 topic managers + BRC-24
  lookup services + storage into one submit/lookup engine.
- :class:`OverlayStorage` / :class:`InMemoryOverlayStorage` — the
  topical UTXO set.
- :func:`bsv_brc.overlay.adapters.asgi.create_overlay_app` — a Starlette
  app exposing ``/submit`` + ``/lookup``.

Bring the interfaces from their home packages:
    from bsv_brc.brc22 import TopicManager
    from bsv_brc.brc24 import LookupService, OutputRef
"""

from bsv_brc.overlay.engine import (
    OverlayEngine,
    UnknownServiceError,
    UnknownTopicError,
)
from bsv_brc.overlay.storage import (
    InMemoryOverlayStorage,
    OverlayStorage,
    SqliteOverlayStorage,
    StoredOutput,
)
from bsv_brc.overlay.topic_root import (
    EMPTY_STATE_ROOT,
    outpoint_string,
    state_root,
)

__all__ = [
    "OverlayEngine",
    "UnknownServiceError",
    "UnknownTopicError",
    "OverlayStorage",
    "InMemoryOverlayStorage",
    "SqliteOverlayStorage",
    "StoredOutput",
    # per-topic state root (matches overlay.peck.to /state)
    "state_root",
    "outpoint_string",
    "EMPTY_STATE_ROOT",
]
