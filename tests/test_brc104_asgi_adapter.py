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
    client_peer = Peer(wallet=client_wallet, transport=client_transport)

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
    # And carry a signature.
    assert response_data["signature"]
