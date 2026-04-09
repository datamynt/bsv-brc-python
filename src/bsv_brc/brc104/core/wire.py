"""Wire-format helpers for BRC-104 general-message payloads.

These mirror the binary encoding used by `bsv.auth.clients.auth_fetch.AuthFetch`
on the client side, exposed as plain functions so the ASGI adapter can
build (server-side) the same bytes the client signed and sign response
payloads in a shape the client knows how to verify.

The format is intentionally a 1:1 copy of upstream — keep it that way.
If `bsv.auth` ever exports these helpers we delete this module and
import directly.
"""

from __future__ import annotations

import struct
from typing import Iterable, Tuple
from urllib.parse import urlsplit

VARINT_NEG_ONE_VALUE = 0xFFFFFFFFFFFFFFFF


def write_varint(buf: bytearray, value: int) -> None:
    if value == VARINT_NEG_ONE_VALUE or value < 0:
        buf.append(0xFF)
        buf.extend(struct.pack("<Q", VARINT_NEG_ONE_VALUE))
    elif value < 0xFD:
        buf.append(value)
    elif value <= 0xFFFF:
        buf.append(0xFD)
        buf.extend(struct.pack("<H", value))
    elif value <= 0xFFFFFFFF:
        buf.append(0xFE)
        buf.extend(struct.pack("<I", value))
    else:
        buf.append(0xFF)
        buf.extend(struct.pack("<Q", value))


def write_string(buf: bytearray, s: str) -> None:
    encoded = s.encode("utf-8")
    write_varint(buf, len(encoded))
    buf.extend(encoded)


def select_request_headers(headers: Iterable[Tuple[str, str]]) -> list[Tuple[str, str]]:
    """Filter and normalise headers exactly the way auth_fetch does.

    Includes:
    - any ``x-bsv-*`` header that is NOT an ``x-bsv-auth-*`` header
    - ``authorization``
    - ``content-type`` (without parameters; only the bare media type)
    """
    selected: list[Tuple[str, str]] = []
    for k, v in headers:
        key = k.lower()
        if (key.startswith("x-bsv-") and not key.startswith("x-bsv-auth")) or key == "authorization":
            selected.append((key, v))
        elif key.startswith("content-type"):
            content_type = v.split(";")[0].strip()
            selected.append((key, content_type))
    selected.sort(key=lambda x: x[0])
    return selected


def _determine_body(method: str, body: bytes, included_headers: list[Tuple[str, str]]) -> bytes:
    methods_with_body = {"POST", "PUT", "PATCH", "DELETE"}
    if not body and method.upper() in methods_with_body:
        for k, v in included_headers:
            if k == "content-type" and "application/json" in v:
                return b"{}"
        return b""
    return body


def build_request_payload(
    *,
    request_nonce: bytes,
    method: str,
    url_path: str,
    url_query: str,
    headers: Iterable[Tuple[str, str]],
    body: bytes,
) -> bytes:
    """Reconstruct the bytes a BRC-104 client signed for an HTTP request.

    Mirrors ``AuthFetch.serialize_request``. ``url_query`` should be the
    raw query string (without the leading ``?``); pass an empty string
    if there is none.
    """
    if len(request_nonce) != 32:
        raise ValueError("request_nonce must be exactly 32 bytes")

    buf = bytearray()
    buf.extend(request_nonce)
    write_string(buf, method)

    if url_path:
        write_string(buf, url_path)
    else:
        write_varint(buf, VARINT_NEG_ONE_VALUE)

    if url_query:
        write_string(buf, "?" + url_query)
    else:
        write_varint(buf, VARINT_NEG_ONE_VALUE)

    included = select_request_headers(headers)
    write_varint(buf, len(included))
    for k, v in included:
        write_string(buf, k)
        write_string(buf, v)

    body_to_write = _determine_body(method, body, included)
    if body_to_write:
        write_varint(buf, len(body_to_write))
        buf.extend(body_to_write)
    else:
        write_varint(buf, VARINT_NEG_ONE_VALUE)

    return bytes(buf)


def select_response_headers(headers: Iterable[Tuple[str, str]]) -> list[Tuple[str, str]]:
    """Headers that go into a signed response payload.

    auth_fetch's reader includes everything except the ``x-bsv-auth-*``
    headers themselves (those are sent uninterpreted alongside the
    payload). ``authorization`` is included; everything in ``x-bsv-*``
    that is not auth-control is included.
    """
    selected: list[Tuple[str, str]] = []
    for k, v in headers:
        key = k.lower()
        if key.startswith("x-bsv-auth"):
            continue
        if (
            key.startswith("x-bsv-")
            or key == "authorization"
            or key.startswith("content-type")
        ):
            if key.startswith("content-type"):
                v = v.split(";")[0].strip()
            selected.append((key, v))
    selected.sort(key=lambda x: x[0])
    return selected


def build_response_payload(
    *,
    request_nonce: bytes,
    status_code: int,
    headers: Iterable[Tuple[str, str]],
    body: bytes,
) -> bytes:
    """Build the bytes the server signs for an HTTP response.

    The first 32 bytes echo the client's ``request_nonce`` so the
    client can match the signed payload to its outstanding request.
    Mirrors ``AuthFetch._try_parse_binary_general`` in reverse.
    """
    if len(request_nonce) != 32:
        raise ValueError("request_nonce must be exactly 32 bytes")

    buf = bytearray()
    buf.extend(request_nonce)
    write_varint(buf, status_code)

    included = select_response_headers(headers)
    write_varint(buf, len(included))
    for k, v in included:
        write_string(buf, k)
        write_string(buf, v)

    if body:
        write_varint(buf, len(body))
        buf.extend(body)
    else:
        write_varint(buf, VARINT_NEG_ONE_VALUE)

    return bytes(buf)


def split_path_query(raw_path: str) -> Tuple[str, str]:
    """Split an ASGI ``path`` (which may include ``?query``) into parts."""
    parts = urlsplit(raw_path)
    return parts.path, parts.query


__all__ = [
    "build_request_payload",
    "build_response_payload",
    "select_request_headers",
    "select_response_headers",
    "split_path_query",
    "write_string",
    "write_varint",
]
