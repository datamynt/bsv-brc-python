"""
BRC-103 message signing and verification.

NOT YET IMPLEMENTED. Will use BRC-42 key derivation with the protocol ID
`"authrite message signature"`, security level 2, and key ID format
`"<counterparty_nonce> <sender_nonce>"` (per spec).

This is the most wire-compat-sensitive module in BRC-103. It will be
implemented only after we have test vectors from a reference
implementation (`@bsv/sdk` or `bsv-blockchain/py-middleware`) so we can
verify byte-for-byte agreement before shipping.

See ROADMAP.md for the implementation plan.
"""

from __future__ import annotations

# BRC-43 protocol identifier for general message signing (per spec).
AUTHRITE_PROTOCOL_ID = "authrite message signature"
AUTHRITE_SECURITY_LEVEL = 2

# Intentionally no implementation yet — see module docstring.
