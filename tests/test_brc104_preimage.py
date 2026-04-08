"""
Tests for BRC-104 signing pre-image construction.

These tests use hand-derived expected byte sequences to lock in the
exact wire format. Every test failure here means a wire-compat
regression — the pre-image MUST be byte-for-byte identical with
`bsv-blockchain/py-middleware` (and by extension `@bsv/sdk`) for
signatures to verify cross-implementation.

If a test breaks: do NOT just update the expected bytes. Investigate
what changed in the encoder, fix it, and confirm the new bytes match
the reference implementation.
"""

import base64

import pytest

from bsv_brc.brc104 import (
    VARINT_NEG_ONE,
    build_request_preimage,
    build_response_preimage,
    encode_string,
    encode_varint,
    filter_request_headers,
    filter_response_headers,
    normalize_content_type,
)


# ---------------------------------------------------------------------------
# encode_varint
# ---------------------------------------------------------------------------


class TestEncodeVarint:
    def test_zero(self):
        assert encode_varint(0) == b"\x00"

    def test_small(self):
        assert encode_varint(1) == b"\x01"
        assert encode_varint(0xFC) == b"\xfc"

    def test_u16_boundary(self):
        # 0xFD triggers the 2-byte little-endian form
        assert encode_varint(0xFD) == b"\xfd\xfd\x00"
        assert encode_varint(0xFFFF) == b"\xfd\xff\xff"

    def test_u32_boundary(self):
        assert encode_varint(0x10000) == b"\xfe\x00\x00\x01\x00"
        assert encode_varint(0xFFFFFFFF) == b"\xfe\xff\xff\xff\xff"

    def test_u64(self):
        assert encode_varint(0x100000000) == b"\xff" + (0x100000000).to_bytes(8, "little")

    def test_negative_one_sentinel(self):
        # The "absent" marker: 0xFF + 8 bytes of 0xFF (= 2^64-1 unsigned).
        assert encode_varint(-1) == b"\xff" * 9
        assert encode_varint(-1) == VARINT_NEG_ONE

    def test_other_negatives_rejected(self):
        with pytest.raises(ValueError):
            encode_varint(-2)
        with pytest.raises(ValueError):
            encode_varint(-100)


# ---------------------------------------------------------------------------
# encode_string
# ---------------------------------------------------------------------------


class TestEncodeString:
    def test_empty(self):
        # varint(0) + zero bytes = single 0x00 byte
        assert encode_string("") == b"\x00"

    def test_ascii(self):
        # varint(3) + "GET"
        assert encode_string("GET") == b"\x03GET"

    def test_utf8_multibyte(self):
        # "æ" is 2 UTF-8 bytes
        encoded = encode_string("æ")
        assert encoded == b"\x02\xc3\xa6"

    def test_long(self):
        # 256 chars triggers the 2-byte varint length form
        s = "a" * 256
        encoded = encode_string(s)
        assert encoded == b"\xfd\x00\x01" + b"a" * 256


# ---------------------------------------------------------------------------
# normalize_content_type
# ---------------------------------------------------------------------------


class TestNormalizeContentType:
    def test_no_params(self):
        assert normalize_content_type("application/json") == "application/json"

    def test_strips_charset(self):
        assert normalize_content_type("application/json; charset=utf-8") == "application/json"

    def test_strips_multiple_params(self):
        assert normalize_content_type("text/html; charset=utf-8; boundary=xxx") == "text/html"

    def test_strips_whitespace(self):
        assert normalize_content_type("  application/json  ") == "application/json"


# ---------------------------------------------------------------------------
# Header filtering
# ---------------------------------------------------------------------------


class TestFilterRequestHeaders:
    def test_includes_authorization(self):
        result = filter_request_headers([("Authorization", "Bearer xyz")])
        assert result == [("authorization", "Bearer xyz")]

    def test_includes_content_type_normalized(self):
        result = filter_request_headers([("Content-Type", "application/json; charset=utf-8")])
        assert result == [("content-type", "application/json")]

    def test_includes_x_bsv_non_auth(self):
        result = filter_request_headers([("X-Bsv-Custom", "foo")])
        assert result == [("x-bsv-custom", "foo")]

    def test_excludes_x_bsv_auth(self):
        result = filter_request_headers([("X-Bsv-Auth-Identity-Key", "02abc...")])
        assert result == []

    def test_excludes_unrelated(self):
        result = filter_request_headers([
            ("User-Agent", "test"),
            ("Accept", "*/*"),
            ("Cookie", "session=xyz"),
        ])
        assert result == []

    def test_sorted_lexicographically(self):
        result = filter_request_headers([
            ("X-Bsv-Zeta", "z"),
            ("Authorization", "Bearer xyz"),
            ("X-Bsv-Alpha", "a"),
            ("Content-Type", "application/json"),
        ])
        keys = [k for k, v in result]
        assert keys == sorted(keys)
        assert keys == ["authorization", "content-type", "x-bsv-alpha", "x-bsv-zeta"]


class TestFilterResponseHeaders:
    def test_excludes_authorization(self):
        # Response side does NOT sign authorization.
        result = filter_response_headers([("Authorization", "Bearer xyz")])
        assert result == []

    def test_excludes_content_type(self):
        # Response side does NOT sign content-type
        # (server middleware mutates it).
        result = filter_response_headers([("Content-Type", "application/json")])
        assert result == []

    def test_includes_x_bsv_non_auth(self):
        result = filter_response_headers([("X-Bsv-Payment-Satoshis-Paid", "100")])
        assert result == [("x-bsv-payment-satoshis-paid", "100")]

    def test_excludes_x_bsv_auth(self):
        result = filter_response_headers([("X-Bsv-Auth-Signature", "30450...")])
        assert result == []


# ---------------------------------------------------------------------------
# build_request_preimage
# ---------------------------------------------------------------------------


class TestBuildRequestPreimage:
    """Hand-computed expected bytes lock in the wire format."""

    def test_minimal_get(self):
        """A bare GET / with no request id, no query, no headers, no body."""
        preimage = build_request_preimage(
            request_id_b64="",
            method="GET",
            pathname="/",
            search="",
            headers=[],
            body=b"",
        )
        # 1. Request ID: empty (no header)
        # 2. Method: encode_string("GET") = b"\x03GET"
        # 3. Pathname: encode_string("/") = b"\x01/"
        # 4. Search: VARINT_NEG_ONE (no query)
        # 5. Headers: encode_varint(0) = b"\x00"
        # 6. Body: VARINT_NEG_ONE (no body)
        expected = b"\x03GET" + b"\x01/" + VARINT_NEG_ONE + b"\x00" + VARINT_NEG_ONE
        assert preimage == expected

    def test_with_request_id(self):
        rid_raw = b"\x01" * 32
        rid_b64 = base64.b64encode(rid_raw).decode("ascii")
        preimage = build_request_preimage(
            request_id_b64=rid_b64,
            method="GET",
            pathname="/",
            search="",
            headers=[],
            body=b"",
        )
        # First 32 bytes are the raw request ID, then the rest of the format.
        assert preimage[:32] == rid_raw
        assert preimage[32:] == b"\x03GET\x01/" + VARINT_NEG_ONE + b"\x00" + VARINT_NEG_ONE

    def test_with_query(self):
        preimage = build_request_preimage(
            request_id_b64="",
            method="GET",
            pathname="/api/data",
            search="?id=42",
            headers=[],
            body=b"",
        )
        # Method "GET" → 0x03 GET
        # Pathname "/api/data" (9 bytes) → 0x09 /api/data
        # Search "?id=42" (6 bytes) → 0x06 ?id=42
        expected = (
            b"\x03GET"
            + b"\x09/api/data"
            + b"\x06?id=42"
            + b"\x00"  # 0 headers
            + VARINT_NEG_ONE  # no body
        )
        assert preimage == expected

    def test_with_body(self):
        body = b"hello"
        preimage = build_request_preimage(
            request_id_b64="",
            method="POST",
            pathname="/echo",
            search="",
            headers=[],
            body=body,
        )
        # Body: varint(5) + "hello" = b"\x05hello"
        expected = (
            b"\x04POST"
            + b"\x05/echo"
            + VARINT_NEG_ONE  # no query
            + b"\x00"  # 0 headers
            + b"\x05hello"
        )
        assert preimage == expected

    def test_with_headers_sorted(self):
        preimage = build_request_preimage(
            request_id_b64="",
            method="GET",
            pathname="/",
            search="",
            headers=[
                ("X-Bsv-Zeta", "z"),
                ("X-Bsv-Alpha", "a"),
                ("X-Bsv-Auth-Identity-Key", "02abc"),  # excluded
                ("User-Agent", "test"),  # excluded
            ],
            body=b"",
        )
        # Filtered + sorted: [("x-bsv-alpha", "a"), ("x-bsv-zeta", "z")]
        # Headers count: 2
        # Then for each: encode_string(key) + encode_string(value)
        expected = (
            b"\x03GET"
            + b"\x01/"
            + VARINT_NEG_ONE
            + b"\x02"  # 2 headers
            + b"\x0bx-bsv-alpha\x01a"
            + b"\x0ax-bsv-zeta\x01z"
            + VARINT_NEG_ONE
        )
        assert preimage == expected

    def test_content_type_normalized_in_preimage(self):
        preimage = build_request_preimage(
            request_id_b64="",
            method="POST",
            pathname="/",
            search="",
            headers=[("Content-Type", "application/json; charset=utf-8")],
            body=b"{}",
        )
        # Content-Type should be normalized to "application/json"
        # Headers: 1 → varint(1) = 0x01
        # encode_string("content-type") = 0x0c content-type
        # encode_string("application/json") = 0x10 application/json
        expected = (
            b"\x04POST"
            + b"\x01/"
            + VARINT_NEG_ONE
            + b"\x01"
            + b"\x0ccontent-type"
            + b"\x10application/json"
            + b"\x02{}"
        )
        assert preimage == expected


# ---------------------------------------------------------------------------
# build_response_preimage
# ---------------------------------------------------------------------------


class TestBuildResponsePreimage:
    def test_minimal_200(self):
        rid_raw = b"\x02" * 32
        rid_b64 = base64.b64encode(rid_raw).decode("ascii")
        preimage = build_response_preimage(
            request_id_b64=rid_b64,
            status_code=200,
            headers=[],
            body=b"",
        )
        # 1. Request ID: 32 bytes raw
        # 2. Status: varint(200) = 0xc8
        # 3. Headers count: 0
        # 4. Body: VARINT_NEG_ONE
        expected = rid_raw + b"\xc8" + b"\x00" + VARINT_NEG_ONE
        assert preimage == expected

    def test_request_id_padded_when_short(self):
        # If the decoded request ID is shorter than 32 bytes, pad with zeros.
        short = b"\xaa" * 8
        rid_b64 = base64.b64encode(short).decode("ascii")
        preimage = build_response_preimage(
            request_id_b64=rid_b64,
            status_code=200,
            headers=[],
            body=b"",
        )
        expected_rid = short + b"\x00" * 24
        assert preimage[:32] == expected_rid

    def test_402_with_body(self):
        rid_raw = b"\x03" * 32
        rid_b64 = base64.b64encode(rid_raw).decode("ascii")
        body = b'{"err":"pay"}'
        preimage = build_response_preimage(
            request_id_b64=rid_b64,
            status_code=402,
            headers=[],
            body=body,
        )
        # Status 402 → varint: 402 > 0xfc, so 0xfd 0x92 0x01 (LE)
        # 0x192 = 402
        expected_status = b"\xfd\x92\x01"
        # Body: varint(13) = 0x0d, then 13 raw bytes
        expected_body = b"\x0d" + body
        expected = rid_raw + expected_status + b"\x00" + expected_body
        assert preimage == expected

    def test_excludes_non_x_bsv_headers(self):
        rid_raw = b"\x04" * 32
        rid_b64 = base64.b64encode(rid_raw).decode("ascii")
        preimage = build_response_preimage(
            request_id_b64=rid_b64,
            status_code=200,
            headers=[
                ("Content-Type", "application/json"),  # excluded
                ("Authorization", "Bearer xyz"),  # excluded
                ("X-Bsv-Auth-Signature", "30450..."),  # excluded
                ("X-Bsv-Custom", "yes"),  # included
            ],
            body=b"",
        )
        # Only x-bsv-custom should appear
        # x-bsv-custom is 12 bytes → 0x0c
        expected = (
            rid_raw
            + b"\xc8"  # 200
            + b"\x01"  # 1 header
            + b"\x0cx-bsv-custom"
            + b"\x03yes"
            + VARINT_NEG_ONE
        )
        assert preimage == expected
