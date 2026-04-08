"""
BRC-103 type definitions.

Pure dataclasses representing the protocol's message types and session
state. Wire format mapping (snake_case ↔ camelCase) is handled by the
to_dict / from_dict methods so the Python API is idiomatic while the
on-wire JSON matches the spec exactly.

Reference: https://bsv.brc.dev/peer-to-peer/0103
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any


# BRC-103 protocol version (current)
BRC103_VERSION = "1.0"

# Message type discriminators (per spec)
MESSAGE_TYPE_INITIAL_REQUEST = "initialRequest"
MESSAGE_TYPE_INITIAL_RESPONSE = "initialResponse"
MESSAGE_TYPE_GENERAL = "general"
MESSAGE_TYPE_CERTIFICATE_REQUEST = "certificateRequest"
MESSAGE_TYPE_CERTIFICATE_RESPONSE = "certificateResponse"


@dataclass
class RequestedCertificates:
    """
    A set of certificates a peer is asking for.

    Per BRC-103, this is sent in initialRequest or certificateRequest to
    tell the counterparty which certificate types are needed and which
    certifiers are trusted to issue them.
    """

    certifiers: list[str]
    """List of trusted certifier public keys (33-byte compressed, hex)."""

    types: dict[str, list[str]]
    """Map of certificateTypeID → list of requested field names."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "certifiers": list(self.certifiers),
            "types": dict(self.types),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestedCertificates:
        return cls(
            certifiers=list(data.get("certifiers", [])),
            types=dict(data.get("types", {})),
        )


@dataclass
class AuthMessage:
    """
    A BRC-103 authentication message.

    Used for all message types: initialRequest, initialResponse,
    general, certificateRequest, certificateResponse.

    Different message types use different subsets of fields:

    initialRequest:
        version, message_type, identity_key, initial_nonce,
        requested_certificates (optional)

    initialResponse:
        version, message_type, identity_key, initial_nonce, your_nonce,
        certificates (optional), signature

    general:
        version, message_type, identity_key, nonce, your_nonce, payload,
        signature, certificates (optional)

    Wire format note: this class uses Python snake_case internally and
    maps to/from the spec's camelCase JSON via to_dict / from_dict.
    """

    version: str = BRC103_VERSION
    message_type: str = ""
    identity_key: str = ""
    """Sender's 33-byte compressed secp256k1 public key, hex-encoded."""

    # Handshake nonces
    initial_nonce: str | None = None
    """Sender's nonce in handshake messages (initialRequest/initialResponse)."""

    your_nonce: str | None = None
    """Echo of the peer's nonce (initialResponse and general messages)."""

    nonce: str | None = None
    """Sender's fresh nonce in general messages."""

    # General message payload
    payload: bytes | None = None
    """Arbitrary message body for general messages."""

    # Authentication
    signature: str | None = None
    """ECDSA signature, hex-encoded."""

    # Certificate exchange
    requested_certificates: RequestedCertificates | None = None
    certificates: list[dict[str, Any]] | None = None
    """List of VerifiableCertificate objects (BRC-52). Schema TBD."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict matching the BRC-103 wire format (camelCase)."""
        out: dict[str, Any] = {
            "version": self.version,
            "messageType": self.message_type,
            "identityKey": self.identity_key,
        }
        if self.initial_nonce is not None:
            out["initialNonce"] = self.initial_nonce
        if self.your_nonce is not None:
            out["yourNonce"] = self.your_nonce
        if self.nonce is not None:
            out["nonce"] = self.nonce
        if self.payload is not None:
            # Wire format uses base64 for binary payloads inside JSON.
            out["payload"] = base64.b64encode(self.payload).decode("ascii")
        if self.signature is not None:
            out["signature"] = self.signature
        if self.requested_certificates is not None:
            out["requestedCertificates"] = self.requested_certificates.to_dict()
        if self.certificates is not None:
            out["certificates"] = self.certificates
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthMessage:
        """Parse from a dict in BRC-103 wire format (camelCase)."""
        payload = data.get("payload")
        if payload is not None and isinstance(payload, str):
            payload = base64.b64decode(payload)

        rc_data = data.get("requestedCertificates")
        rc = RequestedCertificates.from_dict(rc_data) if rc_data else None

        return cls(
            version=data.get("version", BRC103_VERSION),
            message_type=data.get("messageType", ""),
            identity_key=data.get("identityKey", ""),
            initial_nonce=data.get("initialNonce"),
            your_nonce=data.get("yourNonce"),
            nonce=data.get("nonce"),
            payload=payload,
            signature=data.get("signature"),
            requested_certificates=rc,
            certificates=data.get("certificates"),
        )


@dataclass
class Session:
    """
    BRC-103 session state for one remote peer.

    Tracks the authenticated channel between the local party and a
    specific remote peer. A peer typically maintains one Session per
    counterparty.
    """

    peer_identity_key: str
    """Peer's 33-byte compressed secp256k1 public key, hex-encoded."""

    session_nonce: str
    """Locally generated 256-bit nonce (base64), our side of the handshake."""

    peer_nonce: str = ""
    """Peer's 256-bit nonce (base64), set after we receive their handshake."""

    is_authenticated: bool = False
    """True after a successful mutual handshake."""

    peer_certificates: list[dict[str, Any]] = field(default_factory=list)
    """Certificates the peer has shared with us. Schema TBD (BRC-52)."""
