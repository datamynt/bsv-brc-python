"""
BRC-103 message signing and verification.

NOT YET IMPLEMENTED. This module will provide pure functions to sign
and verify BRC-103 general messages using BRC-42 key derivation through
a wallet abstraction.

The wire format for the signing pre-image is implemented in
`bsv_brc.brc104.core.preimage` (since the pre-image construction is
HTTP-specific). This module wraps that pre-image with the cryptographic
operations defined by BRC-103.

Cryptographic parameters (verified against
`bsv-blockchain/py-middleware/django/auth_middleware.py`):

- BRC-43 protocol ID: "auth message signature" — security level 2
- Key ID format: "<counterparty_nonce> <sender_nonce>"
  (base64 nonces separated by a single space)
- Counterparty: the OTHER party's identity public key (33-byte
  compressed secp256k1, hex-encoded)
- Data: the binary pre-image bytes from `brc104.core.preimage`

Note on the protocol ID: the BRC-103 spec inherits the wording
"authrite message signature" from BRC-31 (Authrite). The actual
reference implementation in `py-middleware` uses the shorter
"auth message signature". Per a code comment in py-middleware,
"Protocol name must only contain letters, numbers and spaces" (a
BRC-43 validation rule). We match the reference implementation,
NOT the spec wording, because that is what `@bsv/sdk` interoperates
with in practice. This is a deliberate, documented divergence.

See ROADMAP.md for the implementation plan.
"""

from __future__ import annotations

# BRC-43 protocol identifier for general message signing.
#
# This is the string used as the protocol name in the BRC-43 invoice
# number when signing or verifying a BRC-103 general message. It MUST
# match what `@bsv/sdk` and `bsv-blockchain/py-middleware` use, otherwise
# every signature will fail cross-implementation verification — even
# though the math is correct, the derived keys will differ.
AUTH_PROTOCOL_ID = "auth message signature"

# BRC-43 security level for the protocol above.
AUTH_SECURITY_LEVEL = 2


def build_key_id(counterparty_nonce: str, sender_nonce: str) -> str:
    """
    Build the BRC-43 key ID for signing a BRC-103 general message.

    Per the reference implementation, the key ID is the counterparty's
    nonce and the sender's nonce, both base64-encoded, separated by a
    single space character.

    Args:
        counterparty_nonce: The peer's most recent nonce (base64).
        sender_nonce: This party's fresh nonce for this message (base64).

    Returns:
        The key ID string to pass into the wallet's create_signature call.
    """
    return f"{counterparty_nonce} {sender_nonce}"


# Sign / verify functions are intentionally not yet implemented.
# They depend on a wallet abstraction (wallet.create_signature /
# wallet.verify_signature) that we have not yet decided how to surface
# in `bsv-brc`. The decision is whether to:
#   (a) require users to pass in a `bsv-sdk` wallet object, or
#   (b) provide a thin wallet shim built on bsv-sdk's primitives.
# See ROADMAP.md.
