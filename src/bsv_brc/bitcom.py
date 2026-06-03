"""
Bitcom / Bitcoin Schema OP_RETURN — B + MAP + AIP builder and parser.

The single most hand-rolled (and most bug-prone) on-chain primitive in
the peck fleet: every social app emits ``OP_FALSE OP_RETURN`` data using
the B (data), MAP (Magic Attribute Protocol) and AIP (Author Identity
Protocol) prefixes, joined by a ``|`` separator — and that separator has
a load-bearing subtlety: it MUST be pushed as a 1-byte pushdata
(``0x01 0x7c``), never the raw ``0x7c`` byte (which is ``OP_SWAP`` and
silently breaks every parser that splits sections on ``|``). This module
captures the format once, byte-compatible with what ``overlay.peck.to``
admits (its ``readMapSection``) and what the working apps emit.

Build::

    from bsv_brc import bitcom
    script = bitcom.op_return(
        bitcom.b_section("hello world", media_type="text/plain"),
        bitcom.map_set({"app": "peck.to", "type": "post"}),
    )                                   # -> bytes (locking script)

Parse::

    sections = bitcom.parse_script(script_hex_or_bytes)
    sections.map.fields["app"]          # "peck.to"

AIP (authorship): the wallet/frontend normally signs, but the BSM
primitives and verify are here for the read/admission side.

References: B (19Hxig…), MAP (1PuQa7…), AIP (15PciH…); Bitcoin Schema.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Optional, Union

import bsv.compat.bsm as _bsm
from bsv.keys import PrivateKey, PublicKey

__all__ = [
    "B_PREFIX",
    "MAP_PREFIX",
    "AIP_PREFIX",
    "AIP_BITCOIN_ECDSA",
    "push_data",
    "decode_pushdata",
    "op_return",
    "op_return_parts_to_script",
    "b_section",
    "map_set",
    "aip_section",
    "parse_script",
    "ParsedScript",
    "MapSection",
    "BSection",
    "AipSection",
    "bsm_sign",
    "bsm_verify",
    "bsm_recover_address",
    "aip_verify",
]

# Bitcom protocol prefix addresses (Bitcoin Schema standard).
B_PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
MAP_PREFIX = "1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5"
AIP_PREFIX = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"
AIP_BITCOIN_ECDSA = "BITCOIN_ECDSA"

# The section separator is the byte 0x7c ("|") — but on-chain it is a
# 1-byte PUSHDATA, i.e. the two bytes 0x01 0x7c, NOT a raw 0x7c (OP_SWAP).
_PIPE_BYTE = b"\x7c"


def _to_bytes(field_value: Union[str, bytes]) -> bytes:
    if isinstance(field_value, (bytes, bytearray)):
        return bytes(field_value)
    return str(field_value).encode("utf-8")


# --- pushdata ------------------------------------------------------------


def push_data(data: bytes) -> bytes:
    """Minimal Bitcoin pushdata encoding of ``data`` (matches the fleet)."""
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n < 0x100:
        return bytes([0x4C, n]) + data
    if n < 0x10000:
        return bytes([0x4D]) + n.to_bytes(2, "little") + data
    return bytes([0x4E]) + n.to_bytes(4, "little") + data


def decode_pushdata(script: bytes) -> list[bytes]:
    """Decode a sequence of pushdata chunks (after any OP_FALSE/OP_RETURN).

    Skips a leading ``OP_FALSE`` (0x00) + ``OP_RETURN`` (0x6a), or a bare
    ``OP_RETURN``, then reads each pushed data chunk. Non-push opcodes
    other than the pipe are surfaced as their single opcode byte.
    """
    i = 0
    n = len(script)
    # Strip OP_FALSE OP_RETURN / OP_RETURN framing if present.
    if i < n and script[i] == 0x00 and i + 1 < n and script[i + 1] == 0x6A:
        i += 2
    elif i < n and script[i] == 0x6A:
        i += 1

    chunks: list[bytes] = []
    while i < n:
        op = script[i]
        i += 1
        if op == 0x00:
            chunks.append(b"")
        elif op < 0x4C:
            chunks.append(script[i : i + op])
            i += op
        elif op == 0x4C:
            ln = script[i]
            i += 1
            chunks.append(script[i : i + ln])
            i += ln
        elif op == 0x4D:
            ln = int.from_bytes(script[i : i + 2], "little")
            i += 2
            chunks.append(script[i : i + ln])
            i += ln
        elif op == 0x4E:
            ln = int.from_bytes(script[i : i + 4], "little")
            i += 4
            chunks.append(script[i : i + ln])
            i += ln
        else:
            # A bare opcode (e.g. 0x7c if someone wrote the buggy raw pipe).
            chunks.append(bytes([op]))
    return chunks


# --- builders ------------------------------------------------------------


def b_section(
    content: Union[str, bytes],
    media_type: str = "application/octet-stream",
    encoding: str = "binary",
    filename: str = "",
) -> list[bytes]:
    """A B-protocol data section: ``[B, content, media_type, encoding, filename]``."""
    return [
        _to_bytes(B_PREFIX),
        _to_bytes(content),
        _to_bytes(media_type),
        _to_bytes(encoding),
        _to_bytes(filename),
    ]


def map_set(fields: dict[str, Any]) -> list[bytes]:
    """A MAP ``SET`` section: ``[MAP, "SET", k1, v1, k2, v2, ...]``."""
    out: list[bytes] = [_to_bytes(MAP_PREFIX), _to_bytes("SET")]
    for k, v in fields.items():
        out.append(_to_bytes(k))
        out.append(_to_bytes(v))
    return out


def op_return(*sections: list[Union[str, bytes]]) -> bytes:
    """Build an ``OP_FALSE OP_RETURN`` locking script from sections.

    Each section is a list of fields (str or bytes); sections are joined
    by the correctly-encoded ``|`` pushdata separator.
    """
    out = bytearray([0x00, 0x6A])  # OP_FALSE OP_RETURN
    for idx, section in enumerate(sections):
        if idx > 0:
            out += push_data(_PIPE_BYTE)
        for f in section:
            out += push_data(_to_bytes(f))
    return bytes(out)


def op_return_parts_to_script(parts: list[Any]) -> bytes:
    """Flat-parts builder, drop-in for the apps' ``parts_to_script_hex``.

    ``parts`` is a flat list where ``"|"`` is the section separator,
    ``"HEX:<hex>"`` pushes raw hex, ``bytes`` push as-is, and any other
    value is UTF-8 encoded. Emits the pipe as a proper ``0x01 0x7c``
    pushdata (fixing the common raw-``0x7c`` bug).
    """
    out = bytearray([0x00, 0x6A])
    for part in parts:
        if part == "|":
            out += push_data(_PIPE_BYTE)
        elif isinstance(part, str) and part.startswith("HEX:"):
            out += push_data(bytes.fromhex(part[4:]))
        elif isinstance(part, (bytes, bytearray)):
            out += push_data(bytes(part))
        else:
            out += push_data(str(part).encode("utf-8"))
    return bytes(out)


# --- parsing -------------------------------------------------------------


def _text(b: bytes) -> Optional[str]:
    try:
        return b.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None


@dataclass
class BSection:
    content: Optional[bytes] = None
    media_type: Optional[str] = None
    encoding: Optional[str] = None
    filename: Optional[str] = None


@dataclass
class MapSection:
    app: Optional[str] = None
    type: Optional[str] = None
    action: Optional[str] = None
    fields: dict[str, str] = field(default_factory=dict)


@dataclass
class AipSection:
    algorithm: Optional[str] = None
    address: Optional[str] = None
    signature: Optional[bytes] = None


@dataclass
class ParsedScript:
    b: Optional[BSection] = None
    map: Optional[MapSection] = None
    aip: Optional[AipSection] = None
    sections: list[list[bytes]] = field(default_factory=list)


def _split_sections(chunks: list[bytes]) -> list[list[bytes]]:
    sections: list[list[bytes]] = []
    cur: list[bytes] = []
    for c in chunks:
        if c == _PIPE_BYTE:
            if cur:
                sections.append(cur)
            cur = []
        else:
            cur.append(c)
    if cur:
        sections.append(cur)
    return sections


def parse_script(script: Union[str, bytes]) -> ParsedScript:
    """Parse a Bitcoin-Schema OP_RETURN script into B / MAP / AIP sections.

    Accepts a hex string or raw bytes. Mirrors overlay.peck.to's
    ``readMapSection`` section split (on the ``|`` pushdata) and field
    layout, so a script this module builds round-trips and a script the
    overlay admits parses identically.
    """
    raw = bytes.fromhex(script) if isinstance(script, str) else bytes(script)
    chunks = decode_pushdata(raw)
    sections = _split_sections(chunks)
    parsed = ParsedScript(sections=sections)
    for s in sections:
        if not s:
            continue
        head = _text(s[0])
        if head == B_PREFIX and len(s) >= 2:
            parsed.b = BSection(
                content=s[1] if len(s) > 1 else None,
                media_type=_text(s[2]) if len(s) > 2 else None,
                encoding=_text(s[3]) if len(s) > 3 else None,
                filename=_text(s[4]) if len(s) > 4 else None,
            )
        elif head == MAP_PREFIX and len(s) >= 3 and _text(s[1]) == "SET":
            m = MapSection()
            j = 2
            while j + 1 < len(s):
                k = _text(s[j])
                v = _text(s[j + 1])
                if k is not None and v is not None:
                    m.fields[k] = v
                j += 2
            m.app = m.fields.get("app")
            m.type = m.fields.get("type")
            m.action = m.fields.get("action")
            parsed.map = m
        elif head == AIP_PREFIX and len(s) >= 3:
            parsed.aip = AipSection(
                algorithm=_text(s[1]),
                address=_text(s[2]),
                signature=s[3] if len(s) > 3 else None,
            )
    return parsed


# --- BSM / AIP (authorship) ----------------------------------------------


def bsm_sign(message: bytes, private_key: PrivateKey) -> str:
    """Bitcoin Signed Message over ``message`` -> base64 (the AIP signature)."""
    return _bsm.sign(message, private_key, mode="base64")


def bsm_verify(message: bytes, signature: Union[str, bytes], public_key: PublicKey) -> bool:
    """Verify a BSM signature against a known public key."""
    try:
        return _bsm.verify(message, signature, public_key)
    except Exception:
        return False


def bsm_recover_address(message: bytes, signature_b64: str) -> Optional[str]:
    """Recover the signer's address from a base64 BSM signature.

    BSM puts the recovery flag in the first byte (27..34); coincurve
    wants it last (0..3), so we re-lay the 65-byte signature before
    recovery. Returns the P2PKH address, or None on malformed input.
    """
    try:
        raw = base64.b64decode(signature_b64)
        if len(raw) != 65:
            return None
        recid = (raw[0] - 27) & 0x03
        cc_sig = raw[1:65] + bytes([recid])
        pub = _bsm.recover_public_key(cc_sig, _bsm.magic_hash(message))
        return pub.address()
    except Exception:
        return None


def aip_section(
    message: bytes, private_key: PrivateKey, algorithm: str = AIP_BITCOIN_ECDSA
) -> list[bytes]:
    """Build an AIP section ``[AIP, algorithm, address, signature]`` over ``message``.

    ``message`` is the data to attribute (callers building a full
    Bitcoin-Schema script sign the concatenation of the preceding section
    payloads). The signature is the raw 65 bytes (base64 BSM decoded).
    """
    sig_b64 = bsm_sign(message, private_key)
    return [
        _to_bytes(AIP_PREFIX),
        _to_bytes(algorithm),
        _to_bytes(private_key.address()),
        base64.b64decode(sig_b64),
    ]


def aip_verify(message: bytes, address: str, signature: Union[str, bytes]) -> bool:
    """Verify an AIP signature: does ``signature`` over ``message`` come from ``address``?

    ``signature`` may be base64 (str) or the raw 65 bytes (as carried in
    the script). The caller supplies the signed ``message`` (the AIP
    signed-data convention is application-defined; this verifies a given
    message/address/signature triple unambiguously).
    """
    sig_b64 = (
        signature
        if isinstance(signature, str)
        else base64.b64encode(bytes(signature)).decode("ascii")
    )
    recovered = bsm_recover_address(message, sig_b64)
    return recovered is not None and recovered == address
