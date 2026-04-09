"""
BRC-104: HTTP Transport for BRC-103 Mutual Authentication.

As of bsv-brc 0.2.0 the BRC-103/104 protocol logic itself lives in the
official `bsv.auth` module shipped by `bsv-sdk>=2.0.0b1`. This package
no longer reimplements the wire format. Instead it provides:

- `bsv_brc.brc104.core.headers` — header name constants, kept here so
  framework adapters can reference them without importing the whole
  bsv.auth surface.
- `bsv_brc.brc104.adapters` — per-framework adapters (ASGI/WSGI/...)
  that wrap `bsv.auth.Peer` for Starlette, FastAPI, FastHTML, Litestar,
  Django and Flask.

For low-level wire-format work import directly from `bsv.auth`:

    from bsv.auth import Peer, AuthMessage, SessionManager
    from bsv.auth.transports.simplified_http_transport import (
        SimplifiedHTTPTransport,
    )
    from bsv.auth.clients.auth_fetch import AuthFetch

Reference: https://bsv.brc.dev/peer-to-peer/0104
"""

from bsv_brc.brc104.core.headers import (
    BRC104_VERSION,
    WELL_KNOWN_AUTH_PATH,
    HEADER_VERSION,
    HEADER_IDENTITY_KEY,
    HEADER_NONCE,
    HEADER_YOUR_NONCE,
    HEADER_SIGNATURE,
    HEADER_REQUEST_ID,
    HEADER_MESSAGE_TYPE,
    HEADER_REQUESTED_CERTIFICATES,
    AUTH_HEADER_PREFIX,
    ALL_AUTH_HEADERS,
)

__all__ = [
    "BRC104_VERSION",
    "WELL_KNOWN_AUTH_PATH",
    "HEADER_VERSION",
    "HEADER_IDENTITY_KEY",
    "HEADER_NONCE",
    "HEADER_YOUR_NONCE",
    "HEADER_SIGNATURE",
    "HEADER_REQUEST_ID",
    "HEADER_MESSAGE_TYPE",
    "HEADER_REQUESTED_CERTIFICATES",
    "AUTH_HEADER_PREFIX",
    "ALL_AUTH_HEADERS",
]
