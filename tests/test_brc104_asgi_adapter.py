"""Tests for the BRC-104 ASGI middleware around bsv.auth.Peer."""

from __future__ import annotations

import json

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from bsv.auth.peer import Peer
from bsv.keys import PrivateKey
from bsv.wallet.wallet_impl import ProtoWallet

from bsv_brc.brc104.adapters.asgi import (
    AuthMiddleware,
    WELL_KNOWN_AUTH_PATH,
    _CapturingTransport,
    _WalletShim,
    _auth_message_from_dict,
    _auth_message_to_dict,
    _response_slot,
)


def _hello(_request):
    return PlainTextResponse("hello")


def _make_app() -> Starlette:
    return Starlette(routes=[Route("/", _hello)])


def _make_wallet() -> ProtoWallet:
    return ProtoWallet(PrivateKey())


def test_non_auth_path_passes_through() -> None:
    app = AuthMiddleware(_make_app(), wallet=_make_wallet())
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.text == "hello"


def test_get_on_auth_path_is_method_not_allowed() -> None:
    app = AuthMiddleware(_make_app(), wallet=_make_wallet())
    client = TestClient(app)
    resp = client.get(WELL_KNOWN_AUTH_PATH)
    assert resp.status_code == 405


def test_empty_body_is_bad_request() -> None:
    app = AuthMiddleware(_make_app(), wallet=_make_wallet())
    client = TestClient(app)
    resp = client.post(WELL_KNOWN_AUTH_PATH, content=b"")
    assert resp.status_code == 400


def test_invalid_json_is_bad_request() -> None:
    app = AuthMiddleware(_make_app(), wallet=_make_wallet())
    client = TestClient(app)
    resp = client.post(WELL_KNOWN_AUTH_PATH, content=b"not json")
    assert resp.status_code == 400


def test_initial_request_handshake_returns_initial_response() -> None:
    """End-to-end: a client-side Peer's initialRequest is accepted by the
    middleware and produces a well-formed initialResponse from the
    server-side bsv.auth.Peer."""

    server_wallet = _make_wallet()
    middleware = AuthMiddleware(_make_app(), wallet=server_wallet)
    client = TestClient(middleware)

    # Build a real initialRequest by running a client-side Peer against
    # an in-process capturing transport. We do not start a real network
    # transport on the client side — we only need the bytes of its first
    # outbound message.
    client_wallet = _make_wallet()
    client_transport = _CapturingTransport()
    client_peer = Peer(wallet=_WalletShim(client_wallet), transport=client_transport)

    captured: list = []
    token = _response_slot.set(captured)
    try:
        err = client_peer.initiate_handshake(
            server_wallet.public_key, max_wait_time_ms=100
        )
    finally:
        _response_slot.reset(token)

    # initiate_handshake is allowed to return an Exception when it
    # cannot complete the round trip (because no real transport is
    # delivering the response back) — we only care that the outbound
    # initialRequest was emitted.
    assert captured, f"client peer produced no outbound message (err={err})"
    initial_request = captured[0]
    assert initial_request.message_type == "initialRequest"

    body = json.dumps(
        _auth_message_to_dict(initial_request), default=str
    ).encode("utf-8")
    resp = client.post(
        WELL_KNOWN_AUTH_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )

    assert resp.status_code == 200, resp.text
    response_data = resp.json()
    assert response_data["messageType"] == "initialResponse"
    # The server identifies itself with its own identity key.
    assert response_data["identityKey"]
    # initialResponse must echo the client's initial_nonce as yourNonce.
    assert response_data["yourNonce"] == initial_request.initial_nonce


def _drive_handshake(client: TestClient, server_pub) -> tuple[Peer, ProtoWallet, dict]:
    """Run a full BRC-103 handshake against the middleware.

    Returns the client-side Peer, its wallet, and the parsed
    initialResponse dict so callers can extract the server nonce that
    must be echoed as ``your_nonce`` on subsequent general messages.
    """
    client_wallet = _make_wallet()
    client_transport = _CapturingTransport()
    client_peer = Peer(wallet=_WalletShim(client_wallet), transport=client_transport)

    captured: list = []
    token = _response_slot.set(captured)
    try:
        client_peer.initiate_handshake(server_pub, max_wait_time_ms=100)
    finally:
        _response_slot.reset(token)

    initial_request = captured[0]
    body = json.dumps(
        _auth_message_to_dict(initial_request), default=str
    ).encode("utf-8")
    resp = client.post(
        WELL_KNOWN_AUTH_PATH,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200, resp.text

    # Feed the initialResponse back into the client peer so its
    # session manager learns the server's identity and nonces. We
    # construct an AuthMessage from the JSON the same way the
    # middleware does on the inbound side.
    server_response_msg = _auth_message_from_dict(resp.json())
    feed_slot: list = []
    feed_token = _response_slot.set(feed_slot)
    try:
        err = client_peer.handle_incoming_message(server_response_msg)
    finally:
        _response_slot.reset(feed_token)
    assert err is None, f"client failed to ingest server initialResponse: {err}"

    return client_peer, client_wallet, resp.json()


def test_general_message_roundtrip_signs_and_verifies() -> None:
    """End-to-end: handshake, then issue a signed GET via the client
    Peer and confirm the middleware verifies it, runs the wrapped app,
    and returns a signed response."""

    server_wallet = _make_wallet()
    middleware = AuthMiddleware(_make_app(), wallet=server_wallet)
    client = TestClient(middleware)

    client_peer, _client_wallet, initial_response = _drive_handshake(
        client, server_wallet.public_key
    )

    # Build the signed request payload exactly the way AuthFetch would.
    import base64
    import os

    from bsv_brc.brc104.core.wire import build_request_payload

    request_nonce = os.urandom(32)
    request_nonce_b64 = base64.b64encode(request_nonce).decode("ascii")

    payload = build_request_payload(
        request_nonce=request_nonce,
        method="GET",
        url_path="/",
        url_query="",
        headers=[],
        body=b"",
    )

    # Use the client peer to sign the payload via to_peer; capture the
    # outbound AuthMessage from its transport.
    out_slot: list = []
    out_token = _response_slot.set(out_slot)
    try:
        send_err = client_peer.to_peer(payload, server_wallet.public_key, 0)
    finally:
        _response_slot.reset(out_token)
    assert send_err is None, f"client to_peer failed: {send_err}"
    assert out_slot, "client peer produced no outbound general message"
    outbound = out_slot[0]

    # Convert the AuthMessage into BRC-104 HTTP headers and POST it.
    headers = {
        "x-bsv-auth-version": outbound.version,
        "x-bsv-auth-identity-key": (
            outbound.identity_key.hex()
            if hasattr(outbound.identity_key, "hex")
            else str(outbound.identity_key)
        ),
        "x-bsv-auth-message-type": "general",
        "x-bsv-auth-nonce": outbound.nonce,
        "x-bsv-auth-your-nonce": outbound.your_nonce,
        "x-bsv-auth-signature": (
            outbound.signature.hex()
            if isinstance(outbound.signature, (bytes, bytearray))
            else "".join(f"{b:02x}" for b in outbound.signature)
        ),
        "x-bsv-auth-request-id": request_nonce_b64,
    }

    resp = client.get("/", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.text == "hello"

    # The middleware must add a server-side signed envelope.
    assert resp.headers.get("x-bsv-auth-identity-key")
    assert resp.headers.get("x-bsv-auth-signature")
    assert resp.headers.get("x-bsv-auth-request-id") == request_nonce_b64
    assert resp.headers.get("x-bsv-auth-your-nonce") == outbound.nonce


def test_general_message_without_auth_headers_passes_through() -> None:
    """A request without any auth headers must reach the wrapped app
    unchanged so the middleware can be dropped in without breaking
    anonymous traffic."""

    middleware = AuthMiddleware(_make_app(), wallet=_make_wallet())
    client = TestClient(middleware)
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.text == "hello"
    # No signed envelope should appear on a passthrough response.
    assert "x-bsv-auth-signature" not in {k.lower() for k in resp.headers.keys()}


def test_general_message_with_bad_signature_is_rejected() -> None:
    """Tampered signatures must be rejected with 401 and never reach
    the wrapped app."""

    server_wallet = _make_wallet()
    middleware = AuthMiddleware(_make_app(), wallet=server_wallet)
    client = TestClient(middleware)

    client_peer, _w, _r = _drive_handshake(client, server_wallet.public_key)

    import base64
    import os

    from bsv_brc.brc104.core.wire import build_request_payload

    request_nonce = os.urandom(32)
    request_nonce_b64 = base64.b64encode(request_nonce).decode("ascii")
    payload = build_request_payload(
        request_nonce=request_nonce,
        method="GET",
        url_path="/",
        url_query="",
        headers=[],
        body=b"",
    )

    out_slot: list = []
    out_token = _response_slot.set(out_slot)
    try:
        client_peer.to_peer(payload, server_wallet.public_key, 0)
    finally:
        _response_slot.reset(out_token)
    outbound = out_slot[0]

    # Flip a byte in the signature.
    bad_sig = bytearray(outbound.signature)
    bad_sig[0] ^= 0xFF

    headers = {
        "x-bsv-auth-version": outbound.version,
        "x-bsv-auth-identity-key": outbound.identity_key.hex(),
        "x-bsv-auth-message-type": "general",
        "x-bsv-auth-nonce": outbound.nonce,
        "x-bsv-auth-your-nonce": outbound.your_nonce,
        "x-bsv-auth-signature": bytes(bad_sig).hex(),
        "x-bsv-auth-request-id": request_nonce_b64,
    }

    resp = client.get("/", headers=headers)
    assert resp.status_code == 401
