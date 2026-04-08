"""
BRC-103 session state machine.

NOT YET IMPLEMENTED. Will manage the lifecycle of a `Session` from
creation through handshake completion to general message exchange.

See ROADMAP.md for the implementation plan.
"""

from __future__ import annotations

# Intentionally left empty. Session dataclass lives in types.py;
# the lifecycle logic (create, update on handshake, expire) will land here.
