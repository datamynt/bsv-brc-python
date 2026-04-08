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


from bsv_brc.brc103.wallet import Wallet


def sign_message(
    wallet: Wallet,
    payload: bytes,
    counterparty_identity_key: str,
    counterparty_nonce: str,
    sender_nonce: str,
) -> bytes:
    """
    Sign a BRC-103 message payload.

    Args:
        wallet: Any object satisfying the `Wallet` Protocol. The signer's
            identity key is whatever this wallet wraps.
        payload: The bytes to sign — typically the BRC-104 pre-image
            from `bsv_brc.brc104.core.preimage.build_request_preimage`
            or `build_response_preimage`.
        counterparty_identity_key: Hex-encoded compressed public key of
            the OTHER party (the recipient/verifier).
        counterparty_nonce: The other party's most recent nonce (base64).
        sender_nonce: This party's fresh nonce for this message (base64).

    Returns:
        DER-encoded ECDSA signature bytes.
    """
    return wallet.create_signature(
        data=payload,
        protocol_id=AUTH_PROTOCOL_ID,
        security_level=AUTH_SECURITY_LEVEL,
        key_id=build_key_id(counterparty_nonce, sender_nonce),
        counterparty=counterparty_identity_key,
    )


def verify_message(
    wallet: Wallet,
    payload: bytes,
    signature: bytes,
    counterparty_identity_key: str,
    key_id: str,
) -> bool:
    """
    Verify a BRC-103 message signature.

    Args:
        wallet: The verifier's wallet (its identity key receives the message).
        payload: The reconstructed BRC-104 pre-image bytes.
        signature: DER-encoded ECDSA signature received on the wire.
        counterparty_identity_key: Hex-encoded compressed public key of
            the SIGNER.
        key_id: The exact key ID string the signer used, taken
            verbatim from the wire (`"<counterparty_nonce> <sender_nonce>"`
            from the signer's perspective). Pass it through unchanged —
            do not try to swap nonce order on the verifier side.

    Returns:
        True iff the signature is valid for `payload` under
        `counterparty_identity_key` and `key_id`.
    """
    return wallet.verify_signature(
        data=payload,
        signature=signature,
        protocol_id=AUTH_PROTOCOL_ID,
        security_level=AUTH_SECURITY_LEVEL,
        key_id=key_id,
        counterparty=counterparty_identity_key,
    )
