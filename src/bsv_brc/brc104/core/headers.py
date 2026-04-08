"""
BRC-104 HTTP header constants and whitelist sets.

These constants define the wire format for BRC-104 over HTTP. All
header names are lowercase per HTTP convention; servers should treat
incoming headers case-insensitively before matching against these.

Reference: https://bsv.brc.dev/peer-to-peer/0104
"""

from __future__ import annotations


# BRC-104 protocol version (current).
BRC104_VERSION = "1.0"

# Well-known endpoint path for non-general handshake messages
# (initialRequest, initialResponse, certificateRequest, certificateResponse).
# These are exchanged via POST to this path with a JSON body.
WELL_KNOWN_AUTH_PATH = "/.well-known/auth"


# --- x-bsv-auth-* headers ---
# These carry the BRC-103 protocol fields. They are EXCLUDED from the
# signing pre-image because they are either ephemeral parameters or
# are themselves part of the signature itself.

HEADER_VERSION = "x-bsv-auth-version"
HEADER_IDENTITY_KEY = "x-bsv-auth-identity-key"
HEADER_NONCE = "x-bsv-auth-nonce"
HEADER_YOUR_NONCE = "x-bsv-auth-your-nonce"
HEADER_SIGNATURE = "x-bsv-auth-signature"
HEADER_REQUEST_ID = "x-bsv-auth-request-id"
HEADER_MESSAGE_TYPE = "x-bsv-auth-message-type"
HEADER_REQUESTED_CERTIFICATES = "x-bsv-auth-requested-certificates"

# Common prefix for all BRC-104 auth headers. Any header beginning with
# this prefix is excluded from the signing pre-image.
AUTH_HEADER_PREFIX = "x-bsv-auth-"

ALL_AUTH_HEADERS: frozenset[str] = frozenset({
    HEADER_VERSION,
    HEADER_IDENTITY_KEY,
    HEADER_NONCE,
    HEADER_YOUR_NONCE,
    HEADER_SIGNATURE,
    HEADER_REQUEST_ID,
    HEADER_MESSAGE_TYPE,
    HEADER_REQUESTED_CERTIFICATES,
})


# --- Signed-header whitelists ---
# Per BRC-104, only these headers are included in the signing pre-image.

# Headers that BOTH client and server include in the pre-image.
SIGNED_HEADER_WHITELIST_BOTH: frozenset[str] = frozenset({
    "authorization",
})

# Headers that ONLY the client includes. The server omits content-type
# because middleware (e.g. Express) tends to mutate it (appending
# `; charset=utf-8`), making the pre-image ambiguous on the server side.
SIGNED_HEADER_WHITELIST_CLIENT_ONLY: frozenset[str] = frozenset({
    "content-type",
})

# In addition to the above, ALL headers with the `x-bsv-` prefix EXCEPT
# `x-bsv-auth-*` are included in the pre-image. That rule is enforced
# in `preimage.py` rather than as a static set, since the set is open.


def is_auth_header(name: str) -> bool:
    """True if the given header name is a BRC-104 auth header."""
    return name.lower().startswith(AUTH_HEADER_PREFIX)
