"""
BRC-103 handshake message construction and verification.

NOT YET IMPLEMENTED. Will provide pure functions to:
- Build an initialRequest given local identity and a fresh nonce
- Build an initialResponse given a received initialRequest
- Verify an initialResponse against the original initialRequest
- Drive the session state machine through the two-message handshake

Depends on `signing.py` for cryptographic operations, which is itself
blocked on locating wire-compat test vectors against `@bsv/sdk` or
`bsv-blockchain/py-middleware`.

See ROADMAP.md for the implementation plan.
"""

from __future__ import annotations

# Intentionally left empty until signing.py lands.
