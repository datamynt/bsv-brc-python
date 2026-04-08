"""
BRC-103: Peer-to-Peer Mutual Authentication and Certificate Exchange Protocol.

This package implements the transport-agnostic protocol logic. It knows
nothing about HTTP, Starlette, Django, or any other framework — only
about messages, nonces, signatures, and session state.

For HTTP transport, see `bsv_brc.brc104`.
For framework integration, see `bsv_brc.brc104.adapters`.

Reference: https://bsv.brc.dev/peer-to-peer/0103
"""

from bsv_brc.brc103.nonce import generate_nonce, is_valid_nonce
from bsv_brc.brc103.signing import (
    AUTH_PROTOCOL_ID,
    AUTH_SECURITY_LEVEL,
    build_key_id,
    sign_message,
    verify_message,
)
from bsv_brc.brc103.wallet import PrivateKeyWallet, Wallet
from bsv_brc.brc103.types import (
    AuthMessage,
    RequestedCertificates,
    Session,
    MESSAGE_TYPE_INITIAL_REQUEST,
    MESSAGE_TYPE_INITIAL_RESPONSE,
    MESSAGE_TYPE_GENERAL,
    MESSAGE_TYPE_CERTIFICATE_REQUEST,
    MESSAGE_TYPE_CERTIFICATE_RESPONSE,
)

__all__ = [
    "generate_nonce",
    "is_valid_nonce",
    "AUTH_PROTOCOL_ID",
    "AUTH_SECURITY_LEVEL",
    "build_key_id",
    "sign_message",
    "verify_message",
    "Wallet",
    "PrivateKeyWallet",
    "AuthMessage",
    "RequestedCertificates",
    "Session",
    "MESSAGE_TYPE_INITIAL_REQUEST",
    "MESSAGE_TYPE_INITIAL_RESPONSE",
    "MESSAGE_TYPE_GENERAL",
    "MESSAGE_TYPE_CERTIFICATE_REQUEST",
    "MESSAGE_TYPE_CERTIFICATE_RESPONSE",
]
