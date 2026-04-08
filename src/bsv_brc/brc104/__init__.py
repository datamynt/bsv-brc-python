"""
BRC-104: HTTP Transport for BRC-103 Mutual Authentication.

This package wraps the BRC-103 protocol in HTTP. It is structured as
two layers:

- `bsv_brc.brc104.core` — pure, framework-agnostic HTTP logic
  (header constants, signing pre-image construction, session glue).
  Knows nothing about Starlette/Django/Flask.

- `bsv_brc.brc104.adapters` — thin per-framework adapters that
  translate framework-specific request/response objects to and from
  the pure core. One adapter per supported framework family.

To use BRC-104 in your app, import the adapter for your framework:

    from bsv_brc.brc104.adapters.asgi import AuthMiddleware
    # or .django, .flask, etc.

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
from bsv_brc.brc104.core.preimage import (
    VARINT_NEG_ONE,
    REQUEST_ID_LEN,
    encode_varint,
    encode_string,
    normalize_content_type,
    filter_request_headers,
    filter_response_headers,
    build_request_preimage,
    build_response_preimage,
)

__all__ = [
    # headers
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
    # preimage
    "VARINT_NEG_ONE",
    "REQUEST_ID_LEN",
    "encode_varint",
    "encode_string",
    "normalize_content_type",
    "filter_request_headers",
    "filter_response_headers",
    "build_request_preimage",
    "build_response_preimage",
]
