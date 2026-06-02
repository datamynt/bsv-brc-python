"""Tests for the high-level integration helpers (build_brc_app etc.)."""

from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.transaction import Transaction, TransactionOutput
from bsv.wallet.wallet_impl import ProtoWallet

from bsv_brc.brc104.adapters.asgi import AuthMiddleware
from bsv_brc.brc105.types import BSVPayment, PaymentResult
from bsv_brc.integration import (
    PathPricing,
    build_brc_app,
    build_internalize_args,
    get_identity,
    get_payment,
    make_internalize_verifier,
)


def _payment(beef_b64: str) -> BSVPayment:
    return BSVPayment(
        derivation_prefix="pfx",
        derivation_suffix="sfx",
        transaction=beef_b64,
    )


def _beef_b64(satoshis: int = 7) -> str:
    tx = Transaction()
    tx.add_output(
        TransactionOutput(locking_script=Script(b"\x6a\x01\x00"), satoshis=satoshis)
    )
    return base64.b64encode(tx.to_beef()).decode("ascii")


# --- build_internalize_args (pure BRC-29 mapping) ------------------------


def test_build_internalize_args_shape():
    args = build_internalize_args(_payment(_beef_b64()), "02abc", description="d")
    assert args["description"] == "d"
    assert isinstance(args["tx"], bytes)
    remit = args["outputs"][0]["paymentRemittance"]
    assert remit == {
        "derivationPrefix": "pfx",
        "derivationSuffix": "sfx",
        "senderIdentityKey": "02abc",
    }
    assert args["outputs"][0]["protocol"] == "wallet payment"
    assert args["outputs"][0]["outputIndex"] == 0


def test_build_internalize_args_custom_output_index():
    args = build_internalize_args(_payment(_beef_b64()), "02abc", output_index=3)
    assert args["outputs"][0]["outputIndex"] == 3


# --- make_internalize_verifier -------------------------------------------


class _FakeWallet:
    def __init__(self, result):
        self.result = result
        self.seen_args = None

    def internalize_action(self, args, originator=None):
        self.seen_args = args
        return self.result


@pytest.mark.asyncio
async def test_verifier_accepts_and_reports_satoshis():
    wallet = _FakeWallet({"accepted": True, "txid": "deadbeef"})
    verify = make_internalize_verifier(wallet, description="lbl")
    result = await verify(_payment(_beef_b64(satoshis=42)), "02sender")
    assert isinstance(result, PaymentResult)
    assert result.accepted is True
    assert result.tx == "deadbeef"
    assert result.satoshis_paid == 42
    # The wallet received correctly mapped BRC-29 args.
    assert wallet.seen_args["outputs"][0]["paymentRemittance"][
        "senderIdentityKey"
    ] == "02sender"
    assert wallet.seen_args["description"] == "lbl"


@pytest.mark.asyncio
async def test_verifier_raises_on_rejection_with_error():
    wallet = _FakeWallet({"accepted": False, "error": "nope"})
    verify = make_internalize_verifier(wallet)
    with pytest.raises(ValueError, match="nope"):
        await verify(_payment(_beef_b64()), "02sender")


@pytest.mark.asyncio
async def test_verifier_can_skip_satoshi_reporting():
    wallet = _FakeWallet({"accepted": True})
    verify = make_internalize_verifier(wallet, report_satoshis=False)
    result = await verify(_payment(_beef_b64(satoshis=99)), "02sender")
    assert result.satoshis_paid == 0


# --- PathPricing ---------------------------------------------------------


@pytest.mark.asyncio
async def test_path_pricing_maps_and_defaults():
    pricing = PathPricing({"/premium": 100}, default=5)
    premium = SimpleNamespace(url=SimpleNamespace(path="/premium"))
    other = SimpleNamespace(url=SimpleNamespace(path="/other"))
    assert await pricing.calculate_price(premium) == 100
    assert await pricing.calculate_price(other) == 5


# --- accessors -----------------------------------------------------------


def test_get_identity_from_scope():
    req = SimpleNamespace(scope={"bsv_auth": {"identity_key": "02id"}})
    assert get_identity(req) == "02id"


def test_get_identity_none_when_absent():
    req = SimpleNamespace(scope={}, headers={})
    # headers.get returns None -> overall None
    req.headers = SimpleNamespace(get=lambda k: None)
    assert get_identity(req) is None


def test_get_payment_from_state():
    pr = PaymentResult(satoshis_paid=10, accepted=True)
    req = SimpleNamespace(state=SimpleNamespace(payment=pr))
    assert get_payment(req) is pr


# --- build_brc_app composition -------------------------------------------


def _inner_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/", lambda r: PlainTextResponse("open-ish")),
            Route("/health", lambda r: PlainTextResponse("ok")),
        ]
    )


def test_build_brc_app_returns_auth_middleware():
    wallet = ProtoWallet(PrivateKey())
    app = build_brc_app(_inner_app(), wallet=wallet)
    assert isinstance(app, AuthMiddleware)


def test_build_brc_app_health_is_open():
    wallet = ProtoWallet(PrivateKey())
    app = build_brc_app(_inner_app(), wallet=wallet)
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.text == "ok"


def test_build_brc_app_protected_path_requires_identity():
    wallet = ProtoWallet(PrivateKey())
    app = build_brc_app(_inner_app(), wallet=wallet)
    client = TestClient(app)
    # No BRC-103 handshake / identity -> PaymentMiddleware refuses.
    resp = client.get("/")
    assert resp.status_code == 401
