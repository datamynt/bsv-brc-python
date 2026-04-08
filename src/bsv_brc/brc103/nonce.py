"""
BRC-103 nonce generation and validation.

Per the spec, a nonce is a 256-bit cryptographically random value
transmitted as a base64 string. Used to ensure freshness and prevent
replay attacks during handshake and general message exchange.
"""

from __future__ import annotations

import base64
import os


def generate_nonce() -> str:
    """
    Generate a new BRC-103 nonce.

    Returns:
        A 256-bit (32-byte) random value, base64-encoded as a string.
        The encoded length is 44 characters (32 bytes → 44 base64 chars
        including the trailing '=' padding).
    """
    raw = os.urandom(32)
    return base64.b64encode(raw).decode("ascii")


def is_valid_nonce(nonce: str) -> bool:
    """
    Check if a string is a syntactically valid BRC-103 nonce.

    Validates that the input is base64-decodable and decodes to exactly
    32 bytes. Does NOT verify cryptographic origin, freshness, or
    session binding — that is the job of the session layer.

    Args:
        nonce: The candidate nonce string.

    Returns:
        True if the string decodes to exactly 32 bytes of base64.
    """
    if not isinstance(nonce, str):
        return False
    try:
        decoded = base64.b64decode(nonce, validate=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) == 32
