"""
BRC-138: Single-Use Signed Proofs for Request Authentication.

A lightweight mechanism for a server to authenticate that a request was made
by the holder of a wallet identity key — login being the most common example —
in a single request, without a prior challenge round-trip and without a full
BRC-103 mutual-authentication session.

A proof is a small signed payload ``{ action, identityKey, expiresAt, nonce }``
together with a signature over its canonical encoding, created with the
client's signing key derived toward the verifier's identity key (BRC-42/43,
``protocolID = [2, name]``, ``keyID = nonce``, ``counterparty = verifierKey``).
Because the keyID is the per-request nonce, a distinct child key is derived for
every proof — no signing key is ever reused. The verifier checks shape, action,
freshness (expiry-bound, with clock-skew tolerance), the signature, and finally
consumes the nonce in an atomic single-use store.

A request payload MAY be bound into the signature: the canonical bytes are the
auth fields joined by newlines, then a VarInt length prefix, then the exact
payload bytes. Bind the raw bytes you transmit / receive so a tampered body
fails verification.

Wire form (``to_dict`` / ``from_dict``): ``{"data": {...}, "signature": [0-255
byte values]}`` — the signature is transported as an array of bytes per the
spec. Hex strings are also accepted on input for interop with wallets that
hand back DER-hex signatures (e.g. ``@bsv/auth``).

The default ``protocol``, validity window and clock skew match the reference
implementation ``@bsv/auth`` (``DEFAULT_PROTOCOL = [2, "bsv auth proof"]``),
so proofs interoperate across languages out of the box.

References:
    BRC-138: https://bsv.brc.dev/peer-to-peer/0138
    BRC-42:  https://bsv.brc.dev/key-derivation/0042
    BRC-43:  https://bsv.brc.dev/key-derivation/0043
    @bsv/auth: https://www.npmjs.com/package/@bsv/auth
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Sequence

from bsv import PrivateKey, PublicKey

from bsv_brc.crypto.keys import (
    derive_signing_key,
    derive_signing_public_key,
    public_key_from_private,
)

# Matches the reference implementation @bsv/auth (createAuthProof/verifyAuthProof).
DEFAULT_PROTOCOL: tuple[int, str] = (2, "bsv auth proof")
DEFAULT_VALIDITY_WINDOW_MS = 120_000  # 2 minutes
DEFAULT_CLOCK_SKEW_MS = 30_000  # 30 seconds
NONCE_BYTES = 32

_ACTION_RE = re.compile(r"^[A-Za-z0-9 ]+$")


class AuthProofError(ValueError):
    """Raised when a proof cannot be created, parsed or verified."""


def _varint(n: int) -> bytes:
    """Bitcoin variable-length integer encoding (compactint)."""
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _identity_key_bytes(identity_key: str) -> bytes:
    try:
        raw = bytes.fromhex(identity_key)
    except ValueError as exc:
        raise AuthProofError("identityKey must be hex-encoded") from exc
    if len(raw) != 33 or raw[0] not in (0x02, 0x03):
        raise AuthProofError("identityKey must be a 33-byte compressed public key")
    return raw


def _protocol_parts(protocol: Sequence[int | str]) -> tuple[int, str]:
    if len(protocol) != 2 or protocol[0] != 2:
        raise AuthProofError(
            "protocol must be a BRC-43 protocol identifier of the form [2, name]"
        )
    name = str(protocol[1])
    if not name or any(ord(c) < 0x20 for c in name):
        raise AuthProofError(
            "protocol name must not contain control characters"
        )
    return 2, name


def _check_action(action: str) -> None:
    """Actions MUST NOT contain the newline delimiter (or other control chars).

    The spec's examples are "letters, numbers and spaces", but the normative
    requirement is to reject anything that could contain the delimiter; the
    reference implementation only requires a non-empty string. We reject
    control characters (which would break the line-delimited canonical
    encoding) but stay permissive with punctuation so Python and TypeScript
    clients agree.
    """
    if not isinstance(action, str) or not action:
        raise AuthProofError("action must be a non-empty string")
    if any(ord(c) < 0x20 for c in action):
        raise AuthProofError("action must not contain control characters")


def generate_nonce() -> str:
    """Base64 of 32 cryptographically random bytes — a fresh nonce."""
    return base64.b64encode(os.urandom(NONCE_BYTES)).decode("ascii")


@dataclass(frozen=True)
class AuthProofData:
    """The signed statement inside a BRC-138 proof."""

    action: str
    identity_key: str  # hex-encoded, compressed (33-byte) public key
    expires_at: int  # epoch milliseconds
    nonce: str

    def canonical_bytes(self, payload: bytes | None = None) -> bytes:
        """
        The exact bytes signed and verified.

        ``S = action + "\\n" + identityKey + "\\n" + decimal(expiresAt) + "\\n"
        + nonce``, UTF-8 encoded. A bound request payload is appended
        length-prefixed (VarInt) rather than delimited, so arbitrary binary
        content is unambiguous, and an empty bound payload (length 0) is
        distinct from no bound payload (nothing appended).
        """
        head = (
            f"{self.action}\n{self.identity_key}\n{self.expires_at}\n{self.nonce}"
        ).encode("utf-8")
        if payload is None:
            return head
        return head + _varint(len(payload)) + payload

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "identityKey": self.identity_key,
            "expiresAt": self.expires_at,
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthProofData":
        if not isinstance(data, dict):
            raise AuthProofError("proof data must be an object")
        try:
            action = data["action"]
            identity_key = data["identityKey"]
            expires_at = data["expiresAt"]
            nonce = data["nonce"]
        except KeyError as exc:
            raise AuthProofError(
                f"malformed proof: missing field {exc.args[0]}"
            ) from exc
        _check_action(action)
        if not isinstance(identity_key, str) or not identity_key:
            raise AuthProofError("identityKey must be a non-empty string")
        _identity_key_bytes(identity_key)
        if not isinstance(expires_at, (int, float)) or not _is_finite(expires_at):
            raise AuthProofError("expiresAt must be a finite number")
        if not isinstance(nonce, str) or not nonce:
            raise AuthProofError("nonce must be a non-empty string")
        return cls(
            action=action,
            identity_key=identity_key,
            expires_at=int(expires_at),
            nonce=nonce,
        )


def _is_finite(value: Any) -> bool:
    try:
        return float(value) == float(value)  # NaN != NaN
    except (TypeError, ValueError):
        return False


def _decode_signature(signature: Any) -> bytes:
    """Accept the spec's byte-array form plus bytes/hex for interop."""
    if isinstance(signature, (bytes, bytearray)):
        return bytes(signature)
    if isinstance(signature, str):
        try:
            return bytes.fromhex(signature)
        except ValueError:
            raise AuthProofError(
                "signature string must be hex-encoded DER"
            ) from None
    if isinstance(signature, (list, tuple)):
        if all(isinstance(b, int) and 0 <= b <= 255 for b in signature):
            return bytes(signature)
        raise AuthProofError("signature array must contain byte values 0-255")
    raise AuthProofError(
        "signature must be an array of byte values, a hex string, or bytes"
    )


@dataclass(frozen=True)
class AuthProof:
    """A complete BRC-138 authentication proof."""

    data: AuthProofData
    signature: bytes  # DER-encoded ECDSA signature

    def to_dict(self) -> dict[str, Any]:
        """Wire form: ``{"data": {...}, "signature": [byte values]}``."""
        return {"data": self.data.to_dict(), "signature": list(self.signature)}

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> "AuthProof":
        if not isinstance(obj, dict) or not isinstance(obj.get("data"), dict):
            raise AuthProofError("malformed proof: expected {'data': ..., 'signature': ...}")
        if "signature" not in obj:
            raise AuthProofError("malformed proof: missing signature")
        return cls(
            data=AuthProofData.from_dict(obj["data"]),
            signature=_decode_signature(obj["signature"]),
        )


def normalize_body(body: Any) -> bytes:
    """
    Reduce a request payload to the exact bytes bound into a signature.

    Mirrors the reference implementation's ``normalizeBody``: a string is
    UTF-8, bytes are taken as raw bytes, anything else is JSON-encoded then
    UTF-8. ``None`` raises :class:`TypeError` — pass ``payload=None`` to
    create a bodyless proof instead. The reduction MUST be identical on
    client and verifier.
    """
    if body is None:
        raise TypeError("body is None; pass payload=None for a bodyless proof")
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def _payload_bytes(payload: Any) -> bytes | None:
    """Normalize an optional payload to bytes (None = no bound payload)."""
    if payload is None:
        return None
    return normalize_body(payload)


def create_auth_proof(
    identity_private_key: bytes | str,
    verifier_identity_key: str,
    action: str,
    *,
    protocol: Sequence[int | str] = DEFAULT_PROTOCOL,
    validity_window_ms: int = DEFAULT_VALIDITY_WINDOW_MS,
    nonce: str | None = None,
    expires_at: int | None = None,
    payload: Any = None,
    now_ms: int | None = None,
) -> AuthProof:
    """
    Create a BRC-138 authentication proof (client side).

    Args:
        identity_private_key: The client's identity private key (32 bytes or
            hex). Its compressed public key becomes ``data.identityKey``.
        verifier_identity_key: The verifier's identity public key (hex,
            compressed) — the counterparty the signing key is derived toward.
        action: The operation the proof authorizes, e.g. ``"login"``.
        protocol: BRC-43 protocol identifier ``[2, name]``. Defaults to the
            same value as the reference ``@bsv/auth`` implementation.
        validity_window_ms: Proof lifetime in ms (default 120000).
        nonce: Optional explicit nonce; a fresh base64 of 32 random bytes is
            generated when omitted.
        expires_at: Optional explicit expiry (epoch ms); defaults to
            ``now + validity_window_ms``.
        payload: Optional request payload to bind into the signature (string,
            bytes, or JSON-serializable). Pass the exact bytes you transmit.
        now_ms: Injectable clock (epoch ms) for deterministic tests.
    """
    if isinstance(identity_private_key, str):
        identity_private_key = bytes.fromhex(identity_private_key)
    if len(identity_private_key) != 32:
        raise AuthProofError("identity_private_key must be 32 bytes")
    _check_action(action)
    security_level, protocol_name = _protocol_parts(protocol)
    verifier_pub = _identity_key_bytes(verifier_identity_key)
    identity_key = public_key_from_private(identity_private_key).hex()

    now = _now_ms() if now_ms is None else int(now_ms)
    expires = now + validity_window_ms if expires_at is None else int(expires_at)
    nonce = nonce or generate_nonce()

    data = AuthProofData(
        action=action,
        identity_key=identity_key,
        expires_at=expires,
        nonce=nonce,
    )
    signable = data.canonical_bytes(_payload_bytes(payload))

    derived_priv, _ = derive_signing_key(
        identity_private_key,
        security_level,
        protocol_name,
        key_id=nonce,
        counterparty_public_key=verifier_pub,
    )
    # BRC-100 signing: SHA-256 the canonical bytes, then ECDSA-DER sign the
    # digest (matches @bsv/sdk createSignature: hash = sha256(args.data)).
    digest = hashlib.sha256(signable).digest()
    signature = PrivateKey(derived_priv).sign(digest, hasher=lambda x: x)
    return AuthProof(data=data, signature=signature)


def check_auth_proof_data(
    data: AuthProofData,
    expected_action: str,
    *,
    validity_window_ms: int = DEFAULT_VALIDITY_WINDOW_MS,
    clock_skew_ms: int = DEFAULT_CLOCK_SKEW_MS,
    now_ms: int | None = None,
) -> None:
    """
    Pure shape/action/freshness checks (no signature, no single-use lookup).

    Raises :class:`AuthProofError` on the first failed check; returns None on
    success. Mirrors the reference implementation's ``checkAuthSigData``.
    """
    if data.action != expected_action:
        raise AuthProofError("action mismatch")
    now = _now_ms() if now_ms is None else int(now_ms)
    if now >= data.expires_at:
        raise AuthProofError("proof expired")
    if data.expires_at - now > validity_window_ms + clock_skew_ms:
        raise AuthProofError("proof expiry too far in the future")


def verify_auth_proof(
    verifier_private_key: bytes | str,
    proof: AuthProof | dict[str, Any],
    expected_action: str,
    *,
    protocol: Sequence[int | str] = DEFAULT_PROTOCOL,
    validity_window_ms: int = DEFAULT_VALIDITY_WINDOW_MS,
    clock_skew_ms: int = DEFAULT_CLOCK_SKEW_MS,
    single_use_store: Any = None,
    payload: Any = None,
    now_ms: int | None = None,
) -> str:
    """
    Verify a BRC-138 proof (server side).

    Performs, in order: shape, action, freshness, signature, then the atomic
    single-use nonce consumption. Any failure raises :class:`AuthProofError`.
    On success returns the authenticated identity key (hex) — treat it as the
    authenticated subject.

    Args:
        verifier_private_key: The verifier's identity private key, used to
            re-derive the client's child signing public key.
        proof: An :class:`AuthProof` or its wire dict.
        expected_action: The only action this proof may authorize.
        single_use_store: Optional :class:`~bsv_brc.brc138.store.SingleUseStore`
            (or any object with ``insert_if_not_exists(nonce, expires_at) ->
            bool``). If omitted, single-use is NOT enforced — pass one in
            production. The store is only consulted after the signature check
            passes, so invalid proofs never populate it.
        payload: The raw request payload bytes to bind for verification, when
            the action is expected to carry one. Must be byte-for-byte what
            the client signed.
    """
    if isinstance(verifier_private_key, str):
        verifier_private_key = bytes.fromhex(verifier_private_key)
    if not isinstance(proof, AuthProof):
        proof = AuthProof.from_dict(proof)

    check_auth_proof_data(
        proof.data,
        expected_action,
        validity_window_ms=validity_window_ms,
        clock_skew_ms=clock_skew_ms,
        now_ms=now_ms,
    )

    security_level, protocol_name = _protocol_parts(protocol)
    identity_pub = _identity_key_bytes(proof.data.identity_key)

    try:
        derived_pub = derive_signing_public_key(
            identity_pub,
            security_level,
            protocol_name,
            key_id=proof.data.nonce,
            counterparty_private_key=verifier_private_key,
        )
        signable = proof.data.canonical_bytes(_payload_bytes(payload))
        digest = hashlib.sha256(signable).digest()
        signature_valid = PublicKey(derived_pub).verify(
            proof.signature, digest, hasher=lambda x: x
        )
    except Exception:
        # Any error during verification is a verification failure.
        signature_valid = False
    if not signature_valid:
        raise AuthProofError("invalid signature")

    if single_use_store is not None:
        consumed = single_use_store.insert_if_not_exists(
            proof.data.nonce, proof.data.expires_at
        )
        if not consumed:
            raise AuthProofError("proof already used")

    return proof.data.identity_key


__all__ = [
    "AuthProof",
    "AuthProofData",
    "AuthProofError",
    "DEFAULT_CLOCK_SKEW_MS",
    "DEFAULT_PROTOCOL",
    "DEFAULT_VALIDITY_WINDOW_MS",
    "NONCE_BYTES",
    "check_auth_proof_data",
    "create_auth_proof",
    "generate_nonce",
    "normalize_body",
    "verify_auth_proof",
]
