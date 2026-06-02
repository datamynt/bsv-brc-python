"""
Per-topic state root (peck-social-overlay spec section 3.2).

A deterministic, third-party-reproducible commitment over a topic's
ACTIVE (admitted + unspent) outpoint set. Canonical form:

1. outpoint string = ``"<txid_lowercase_hex>:<vout_decimal>"``
2. dedupe (the root is over a SET)
3. lexicographic ascending sort (byte/ASCII)
4. join with ``"\\n"``
5. ``sha256(utf8)`` -> 64-char lowercase hex
6. empty set -> ``sha256("")`` = ``e3b0c442...``

This matches the ``stateRoot`` that ``overlay.peck.to`` publishes at
``GET /state`` exactly — verified live on 2026-06-02 (the empty-set root
``e3b0c442...`` is asserted in the test suite). So a bsv-brc node and the
live peck overlay agree on a topic's root for the same live UTXO set:
this is a cross-implementation interoperable commitment, not just a
bsv-brc-internal one.

Note this commits to *live unspent* outputs (matching the engine's
liveness model and peck-overlay-schema's ``spent = false`` query); a
coin retained-for-history but spent is not in the root.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

__all__ = [
    "EMPTY_STATE_ROOT",
    "outpoint_string",
    "state_root",
]

# sha256("") — the canonical root of an empty topic. Matches the live
# overlay's stateRoot for a topic with count == 0.
EMPTY_STATE_ROOT = hashlib.sha256(b"").hexdigest()


def outpoint_string(txid: str, vout: int) -> str:
    """Canonical outpoint form ``"<txid_lowercase_hex>:<vout>"``."""
    return f"{txid.lower()}:{vout}"


def state_root(outpoints: Iterable[str]) -> str:
    """Compute the canonical state root over a set of outpoint strings.

    Dedupes, sorts lexicographically, joins with newlines, and returns
    the lowercase hex SHA-256. An empty set yields :data:`EMPTY_STATE_ROOT`.
    """
    unique = sorted(set(outpoints))
    return hashlib.sha256("\n".join(unique).encode("utf-8")).hexdigest()
