"""Tests for BRC-103 message and session types."""

import base64

from bsv_brc.brc103 import (
    AuthMessage,
    RequestedCertificates,
    Session,
    MESSAGE_TYPE_INITIAL_REQUEST,
    MESSAGE_TYPE_INITIAL_RESPONSE,
    MESSAGE_TYPE_GENERAL,
)


class TestRequestedCertificatesRoundtrip:
    def test_roundtrip(self):
        rc = RequestedCertificates(
            certifiers=["02abc...", "03def..."],
            types={"identity-v1": ["email", "name"]},
        )
        d = rc.to_dict()
        assert d == {
            "certifiers": ["02abc...", "03def..."],
            "types": {"identity-v1": ["email", "name"]},
        }
        rc2 = RequestedCertificates.from_dict(d)
        assert rc2 == rc

    def test_empty_defaults(self):
        rc = RequestedCertificates(certifiers=[], types={})
        rc2 = RequestedCertificates.from_dict(rc.to_dict())
        assert rc2 == rc


class TestAuthMessageInitialRequest:
    def test_minimal_initial_request_roundtrip(self):
        msg = AuthMessage(
            message_type=MESSAGE_TYPE_INITIAL_REQUEST,
            identity_key="02" + "a" * 64,
            initial_nonce=base64.b64encode(b"\x00" * 32).decode("ascii"),
        )
        wire = msg.to_dict()
        assert wire["version"] == "1.0"
        assert wire["messageType"] == "initialRequest"
        assert wire["identityKey"] == "02" + "a" * 64
        assert "initialNonce" in wire
        # Optional fields not set → not in wire
        assert "signature" not in wire
        assert "yourNonce" not in wire
        assert "payload" not in wire

        msg2 = AuthMessage.from_dict(wire)
        assert msg2 == msg

    def test_initial_request_with_certificates(self):
        rc = RequestedCertificates(
            certifiers=["02ce11..."],
            types={"identity-v1": ["email"]},
        )
        msg = AuthMessage(
            message_type=MESSAGE_TYPE_INITIAL_REQUEST,
            identity_key="02" + "a" * 64,
            initial_nonce=base64.b64encode(b"\x01" * 32).decode("ascii"),
            requested_certificates=rc,
        )
        wire = msg.to_dict()
        assert wire["requestedCertificates"] == rc.to_dict()

        msg2 = AuthMessage.from_dict(wire)
        assert msg2.requested_certificates == rc


class TestAuthMessageInitialResponse:
    def test_initial_response_with_signature(self):
        msg = AuthMessage(
            message_type=MESSAGE_TYPE_INITIAL_RESPONSE,
            identity_key="03" + "b" * 64,
            initial_nonce=base64.b64encode(b"\x02" * 32).decode("ascii"),
            your_nonce=base64.b64encode(b"\x03" * 32).decode("ascii"),
            signature="3045022100" + "f" * 130,
        )
        wire = msg.to_dict()
        assert wire["yourNonce"] == msg.your_nonce
        assert wire["signature"] == msg.signature

        msg2 = AuthMessage.from_dict(wire)
        assert msg2 == msg


class TestAuthMessageGeneral:
    def test_general_message_with_payload(self):
        payload = b"hello, peer"
        msg = AuthMessage(
            message_type=MESSAGE_TYPE_GENERAL,
            identity_key="02" + "c" * 64,
            nonce=base64.b64encode(b"\x04" * 32).decode("ascii"),
            your_nonce=base64.b64encode(b"\x05" * 32).decode("ascii"),
            payload=payload,
            signature="3045022100" + "1" * 130,
        )
        wire = msg.to_dict()

        # Payload is base64-encoded on the wire
        assert wire["payload"] == base64.b64encode(payload).decode("ascii")
        # General messages use `nonce`, not `initialNonce`
        assert "nonce" in wire
        assert "initialNonce" not in wire

        msg2 = AuthMessage.from_dict(wire)
        assert msg2 == msg
        assert msg2.payload == payload

    def test_empty_payload_roundtrip(self):
        msg = AuthMessage(
            message_type=MESSAGE_TYPE_GENERAL,
            identity_key="02" + "c" * 64,
            nonce=base64.b64encode(b"\x06" * 32).decode("ascii"),
            your_nonce=base64.b64encode(b"\x07" * 32).decode("ascii"),
            payload=b"",
            signature="30" * 35,
        )
        msg2 = AuthMessage.from_dict(msg.to_dict())
        assert msg2.payload == b""


class TestSession:
    def test_create_unauthenticated(self):
        session = Session(
            peer_identity_key="02" + "d" * 64,
            session_nonce=base64.b64encode(b"\x08" * 32).decode("ascii"),
        )
        assert not session.is_authenticated
        assert session.peer_nonce == ""
        assert session.peer_certificates == []

    def test_authenticated_after_handshake(self):
        session = Session(
            peer_identity_key="02" + "e" * 64,
            session_nonce=base64.b64encode(b"\x09" * 32).decode("ascii"),
            peer_nonce=base64.b64encode(b"\x0a" * 32).decode("ascii"),
            is_authenticated=True,
        )
        assert session.is_authenticated
        assert session.peer_nonce != ""
