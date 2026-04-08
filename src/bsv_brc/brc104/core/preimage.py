"""
BRC-104 signing pre-image construction.

The pre-image is the exact byte sequence that gets signed (or verified)
for a BRC-104 general message. It MUST be byte-for-byte identical
between any two implementations that need to interoperate, otherwise
all signatures fail cross-implementation verification even though the
cryptographic math is correct.

This module is the result of carefully porting the wire format from
`bsv-blockchain/py-middleware/django/transport.py` and
`bsv-blockchain/py-middleware/django/auth_middleware.py` (the only
existing Python reference implementation, even though it is Django-
specific). All formatting decisions match those references.

The format is binary, not text. It uses Bitcoin-style varints and
length-prefixed UTF-8 strings, following the same conventions as BSV
transaction serialization.

## Request pre-image layout (client → server)

```
1. Request ID         — 32 raw bytes (base64-decoded), or 0 bytes if missing
2. Method             — encode_string("GET" / "POST" / ...)
3. Pathname           — encode_string("/api/foo") or VARINT_NEG_ONE if empty
4. Search             — encode_string("?id=42") or VARINT_NEG_ONE if empty
                        (note: the leading "?" IS part of the signed value)
5. Headers            — varint(count) followed by encode_string(key) +
                        encode_string(value) for each header, sorted
                        lexicographically by lowercased key
6. Body               — varint(len) + raw bytes, or VARINT_NEG_ONE if empty
```

## Response pre-image layout (server → client)

```
1. Request ID         — 32 bytes (base64-decoded, padded with 0x00 to 32)
2. Status code        — varint
3. Headers            — varint(count) + encode_string pairs, sorted
4. Body               — varint(len) + raw bytes, or VARINT_NEG_ONE if empty
```

## Header inclusion rules

Request side (per `_build_general_message_payload` in py-middleware):
- All `x-bsv-*` headers EXCEPT `x-bsv-auth-*`
- `content-type` (with parameters stripped — see normalize_content_type)
- `authorization`

Response side (per `_build_response_payload` in py-middleware):
- ONLY `x-bsv-*` headers EXCEPT `x-bsv-auth-*`
- (No content-type, no authorization — server middleware tends to mutate
  these so they cannot be reliably signed across implementations)

In both cases, header keys are lowercased before sorting and before
encoding into the pre-image.
"""

from __future__ import annotations

import base64
from typing import Iterable

from bsv_brc.brc104.core.headers import AUTH_HEADER_PREFIX


# The "absent" sentinel for varint fields. Used for missing path,
# missing query, missing body. Encoded as 0xFF followed by 8 bytes of
# 0xFF, which represents 2^64 - 1 as an unsigned 64-bit integer (or
# -1 as a signed 64-bit integer, which is how the TypeScript SDK
# originated this convention).
VARINT_NEG_ONE = bytes([0xFF] * 9)

# Length of the request ID in bytes when present (always 32).
REQUEST_ID_LEN = 32


def encode_varint(n: int) -> bytes:
    """
    Encode an integer as a Bitcoin-style varint.

    Special case: pass -1 to get the "absent" sentinel
    (`0xFF` + 8 bytes `0xFF`), used for missing pathname, query, or body.

    Args:
        n: A non-negative integer, or -1 for the absent sentinel.

    Returns:
        The encoded bytes.
    """
    if n == -1:
        return VARINT_NEG_ONE
    if n < 0:
        raise ValueError(f"varint cannot encode negative integer {n} (use -1 sentinel)")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + n.to_bytes(8, "little")
    raise ValueError(f"varint overflow: {n} exceeds 2^64 - 1")


def encode_string(s: str) -> bytes:
    """
    Encode a UTF-8 string with a varint length prefix.

    This is the format used for headers, method, pathname, query, and
    any other string field in the BRC-104 pre-image.

    Args:
        s: The string to encode.

    Returns:
        varint(byte_length) followed by the UTF-8 bytes.
    """
    s_bytes = s.encode("utf-8")
    return encode_varint(len(s_bytes)) + s_bytes


def normalize_content_type(value: str) -> str:
    """
    Strip parameters from a Content-Type header value.

    `application/json; charset=utf-8` → `application/json`

    Server middleware (especially Express in the JS world) tends to
    append `; charset=utf-8` to outgoing Content-Type headers,
    which would cause the client and server to disagree on the signed
    bytes if we did not normalize. Both client and server normalize
    identically before adding to the pre-image.

    Args:
        value: The raw Content-Type header value.

    Returns:
        The value with everything from the first `;` onward stripped.
    """
    return value.split(";", 1)[0].strip()


def _is_auth_header(name: str) -> bool:
    return name.lower().startswith(AUTH_HEADER_PREFIX)


def _is_x_bsv_non_auth(name: str) -> bool:
    lname = name.lower()
    return lname.startswith("x-bsv-") and not lname.startswith(AUTH_HEADER_PREFIX)


def filter_request_headers(
    headers: Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    """
    Filter and sort request headers per BRC-104 client-side rules.

    Includes:
    - All `x-bsv-*` headers (lowercased) except `x-bsv-auth-*`
    - `content-type` (normalized — parameters stripped)
    - `authorization`

    Header keys are lowercased. Content-Type values are normalized.
    Result is sorted lexicographically by key.

    Args:
        headers: Iterable of (key, value) header pairs.

    Returns:
        Sorted list of (lowercased_key, normalized_value) tuples ready
        to be written into the pre-image.
    """
    result: list[tuple[str, str]] = []
    for key, value in headers:
        lkey = key.lower()
        if lkey == "content-type":
            result.append((lkey, normalize_content_type(value)))
        elif lkey == "authorization":
            result.append((lkey, value))
        elif _is_x_bsv_non_auth(lkey):
            result.append((lkey, value))
        # Everything else is excluded.
    result.sort(key=lambda kv: kv[0])
    return result


def filter_response_headers(
    headers: Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    """
    Filter and sort response headers per BRC-104 server-side rules.

    Includes ONLY `x-bsv-*` headers (lowercased) except `x-bsv-auth-*`.
    No content-type, no authorization — server middleware tends to
    mutate these and cannot reliably reproduce them in the pre-image.

    Args:
        headers: Iterable of (key, value) header pairs.

    Returns:
        Sorted list of (lowercased_key, value) tuples.
    """
    result: list[tuple[str, str]] = []
    for key, value in headers:
        lkey = key.lower()
        if _is_x_bsv_non_auth(lkey):
            result.append((lkey, value))
    result.sort(key=lambda kv: kv[0])
    return result


def _decode_request_id_raw(request_id_b64: str) -> bytes:
    """Decode a base64 request ID. Returns empty bytes if input is empty."""
    if not request_id_b64:
        return b""
    try:
        return base64.b64decode(request_id_b64)
    except Exception:
        return b""


def _decode_request_id_padded(request_id_b64: str) -> bytes:
    """Decode and pad to exactly REQUEST_ID_LEN bytes (response side)."""
    raw = _decode_request_id_raw(request_id_b64)
    return raw[:REQUEST_ID_LEN].ljust(REQUEST_ID_LEN, b"\x00")


def build_request_preimage(
    request_id_b64: str,
    method: str,
    pathname: str,
    search: str,
    headers: Iterable[tuple[str, str]],
    body: bytes,
) -> bytes:
    """
    Build the bytes that get signed for a BRC-104 general request.

    Args:
        request_id_b64: Value of the `x-bsv-auth-request-id` header
            (base64-encoded). May be empty.
        method: HTTP method, e.g. "GET" or "POST".
        pathname: URL path WITHOUT query string, e.g. "/api/data".
            Empty string is allowed (will be encoded as the absent
            sentinel).
        search: Query string WITH leading "?", e.g. "?id=42". Pass
            empty string for no query (will be encoded as absent).
            NOTE: the leading "?" IS part of the signed bytes — pass
            it in if there is a query.
        headers: Iterable of (key, value) header pairs from the request.
            Will be filtered, normalized, and sorted automatically.
        body: Raw request body bytes. Pass `b""` for no body (will be
            encoded as the absent sentinel).

    Returns:
        The complete pre-image bytes ready for signing.
    """
    out = bytearray()

    # 1. Request ID (raw, NOT length-prefixed; usually 32 bytes when present)
    out.extend(_decode_request_id_raw(request_id_b64))

    # 2. Method
    out.extend(encode_string(method))

    # 3. Pathname or absent sentinel
    if pathname:
        out.extend(encode_string(pathname))
    else:
        out.extend(VARINT_NEG_ONE)

    # 4. Search/query or absent sentinel
    if search:
        out.extend(encode_string(search))
    else:
        out.extend(VARINT_NEG_ONE)

    # 5. Headers (filtered, sorted)
    filtered = filter_request_headers(headers)
    out.extend(encode_varint(len(filtered)))
    for key, value in filtered:
        out.extend(encode_string(key))
        out.extend(encode_string(value))

    # 6. Body or absent sentinel
    if body:
        out.extend(encode_varint(len(body)))
        out.extend(body)
    else:
        out.extend(VARINT_NEG_ONE)

    return bytes(out)


def build_response_preimage(
    request_id_b64: str,
    status_code: int,
    headers: Iterable[tuple[str, str]],
    body: bytes,
) -> bytes:
    """
    Build the bytes that get signed for a BRC-104 general response.

    Args:
        request_id_b64: Value of the `x-bsv-auth-request-id` header
            from the original request being responded to. Padded to
            exactly 32 bytes (truncated or zero-extended).
        status_code: HTTP status code, e.g. 200 or 402.
        headers: Iterable of (key, value) response headers. Will be
            filtered to only `x-bsv-*` non-auth headers and sorted.
        body: Raw response body bytes. Pass `b""` for no body (will be
            encoded as the absent sentinel).

    Returns:
        The complete pre-image bytes ready for signing.
    """
    out = bytearray()

    # 1. Request ID (always padded to 32 bytes)
    out.extend(_decode_request_id_padded(request_id_b64))

    # 2. Status code
    out.extend(encode_varint(status_code))

    # 3. Headers (filtered, sorted)
    filtered = filter_response_headers(headers)
    out.extend(encode_varint(len(filtered)))
    for key, value in filtered:
        out.extend(encode_string(key))
        out.extend(encode_string(value))

    # 4. Body or absent sentinel
    if body:
        out.extend(encode_varint(len(body)))
        out.extend(body)
    else:
        out.extend(VARINT_NEG_ONE)

    return bytes(out)
