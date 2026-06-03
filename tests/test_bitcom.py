"""Tests for bsv_brc.bitcom — B/MAP/AIP OP_RETURN builder + parser + AIP."""

from __future__ import annotations

import base64

import pytest

from bsv.keys import PrivateKey

from bsv_brc import bitcom
from bsv_brc.bitcom import (
    AIP_PREFIX,
    B_PREFIX,
    MAP_PREFIX,
    aip_section,
    aip_verify,
    b_section,
    bsm_recover_address,
    bsm_sign,
    bsm_verify,
    decode_pushdata,
    map_set,
    op_return,
    op_return_parts_to_script,
    parse_script,
    push_data,
)


# --- pushdata ------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 75, 76, 255, 256, 600])
def test_pushdata_roundtrip(size):
    data = b"x" * size
    # push_data then decode (with a fake OP_RETURN frame) returns it back.
    script = b"\x00\x6a" + push_data(data)
    chunks = decode_pushdata(script)
    assert chunks == [data]


def test_pushdata_boundary_opcodes():
    assert push_data(b"a")[0] == 1  # direct push
    assert push_data(b"x" * 76)[0] == 0x4C  # OP_PUSHDATA1
    assert push_data(b"x" * 256)[0] == 0x4D  # OP_PUSHDATA2


# --- the load-bearing pipe separator (0x01 0x7c, never raw 0x7c) ---------


def test_pipe_is_one_byte_pushdata_not_raw():
    # "a" | "b" must serialize the pipe as 0x01 0x7c, not a bare 0x7c.
    script = op_return_parts_to_script(["a", "|", "b"])
    assert script.hex() == "006a" + "0161" + "017c" + "0162"
    # raw 0x7c (OP_SWAP) must NOT appear as a standalone opcode between pushes
    assert b"\x01\x7c" in script


def test_op_return_structured_matches_flat_for_pipe():
    structured = op_return(["a"], ["b"])  # two sections
    assert structured.hex() == "006a" + "0161" + "017c" + "0162"


# --- B + MAP build -> parse round trip -----------------------------------


def test_build_and_parse_b_and_map():
    script = op_return(
        b_section("hello world", media_type="text/plain", encoding="utf-8"),
        map_set({"app": "peck.to", "type": "post", "lat": "59.9", "lng": "10.7"}),
    )
    parsed = parse_script(script)

    assert parsed.b is not None
    assert parsed.b.content == b"hello world"
    assert parsed.b.media_type == "text/plain"

    assert parsed.map is not None
    assert parsed.map.app == "peck.to"
    assert parsed.map.type == "post"
    assert parsed.map.fields["lat"] == "59.9"
    assert parsed.map.fields["lng"] == "10.7"


def test_parse_accepts_hex_string():
    script = op_return(map_set({"app": "peck.world", "type": "pin"}))
    parsed = parse_script(script.hex())
    assert parsed.map.app == "peck.world"


def test_prefix_constants_match_bitcoin_schema():
    assert B_PREFIX == "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
    assert MAP_PREFIX == "1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5"
    assert AIP_PREFIX == "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"


# --- BSM primitives ------------------------------------------------------


def test_bsm_sign_verify_recover_roundtrip():
    pk = PrivateKey()
    msg = b"MAP|SET|app|peck.to|type|post"
    sig = bsm_sign(msg, pk)
    assert isinstance(sig, str)  # base64
    assert bsm_verify(msg, sig, pk.public_key()) is True
    assert bsm_verify(b"tampered", sig, pk.public_key()) is False
    assert bsm_recover_address(msg, sig) == pk.address()


# --- AIP build -> parse -> verify ----------------------------------------


def test_aip_section_build_parse_verify():
    pk = PrivateKey()
    signed_data = b"the data being attributed"
    script = op_return(
        map_set({"app": "peck.to", "type": "post"}),
        aip_section(signed_data, pk),
    )
    parsed = parse_script(script)
    assert parsed.aip is not None
    assert parsed.aip.algorithm == "BITCOIN_ECDSA"
    assert parsed.aip.address == pk.address()
    # verify the AIP signature (signature carried as raw 65 bytes in script)
    assert aip_verify(signed_data, parsed.aip.address, parsed.aip.signature) is True
    assert aip_verify(b"wrong data", parsed.aip.address, parsed.aip.signature) is False


def test_aip_verify_accepts_base64_or_bytes():
    pk = PrivateKey()
    msg = b"attr"
    sig_b64 = bsm_sign(msg, pk)
    assert aip_verify(msg, pk.address(), sig_b64) is True
    assert aip_verify(msg, pk.address(), base64.b64decode(sig_b64)) is True


def test_aip_verify_rejects_wrong_address():
    pk, other = PrivateKey(), PrivateKey()
    msg = b"attr"
    sig = bsm_sign(msg, pk)
    assert aip_verify(msg, other.address(), sig) is False
