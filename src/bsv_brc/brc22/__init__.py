"""
BRC-22: Overlay Network Transaction Submission (server side).

py-sdk gives you the *client* side of overlay services — broadcasting a
transaction to topics (``TopicBroadcaster``/``SHIPBroadcaster``) and
querying lookup services (``LookupResolver``). It does not let you *be*
an overlay node. This package fills that gap with the server-side
``/submit`` machinery:

- :class:`TopicManager` — subclass it to define which outputs your
  topic admits (the only application-specific logic BRC-22 leaves open).
- :class:`TopicEngine` — the generic submission loop: parse BEEF, run
  each hosted topic manager, return the topic-keyed admittance map.
- :mod:`bsv_brc.brc22.adapters.asgi` — a mountable ASGI ``/submit``
  endpoint for Starlette/FastAPI/FastHTML/Litestar.

The admittance types are re-exported from ``bsv.overlay_tools`` rather
than redefined, so a manager's output stays wire-compatible with the
official client.

Reference: https://bsv.brc.dev/overlays/0022
"""

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions, TaggedBEEF

from bsv_brc.brc22.engine import TopicEngine, UnknownTopicError
from bsv_brc.brc22.topic_manager import TopicManager

__all__ = [
    "TopicManager",
    "TopicEngine",
    "UnknownTopicError",
    "AdmittanceInstructions",
    "TaggedBEEF",
]
