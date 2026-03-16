"""Integration tests for BRC-105 Starlette middleware."""

import json
import os

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from bsv_brc.brc105 import (
    PaymentMiddleware,
    NonceManager,
    StaticPricing,
    BSVPayment,
    PaymentResult,
)


async def echo_handler(request: Request) -> JSONResponse:
    """Simple handler that returns payment info."""
    payment = getattr(request.state, "payment", None)
    return JSONResponse({
        "ok": True,
        "satoshis_paid": payment.satoshis_paid if payment else 0,
    })


async def health_handler(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def _create_app(
    pricing_satoshis: int = 100,
    verify_result: PaymentResult | None = None,
) -> Starlette:
    """Create a test app with BRC-105 middleware."""

    async def mock_verify(payment: BSVPayment, identity_key: str) -> PaymentResult:
        return verify_result or PaymentResult(
            satoshis_paid=pricing_satoshis,
            accepted=True,
            tx=payment.transaction,
        )

    nonce_manager = NonceManager(secret=os.urandom(32))

    app = Starlette(
        routes=[
            Route("/api/data", echo_handler),
            Route("/health", health_handler),
        ],
    )
    app.add_middleware(
        PaymentMiddleware,
        nonce_manager=nonce_manager,
        pricing=StaticPricing(pricing_satoshis),
        verify_payment=mock_verify,
    )
    return app


class TestPaymentMiddleware:
    """Full 402 flow through Starlette middleware."""

    def test_health_excluded(self):
        """Health endpoint skips payment."""
        app = _create_app()
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_no_auth_returns_401(self):
        """Request without identity key returns 401."""
        app = _create_app()
        client = TestClient(app)
        resp = client.get("/api/data")
        assert resp.status_code == 401
        assert resp.json()["code"] == "ERR_AUTH_REQUIRED"

    def test_no_payment_returns_402(self):
        """Authenticated request without payment returns 402 challenge."""
        app = _create_app()
        client = TestClient(app)
        resp = client.get(
            "/api/data",
            headers={"x-bsv-auth-identity-key": "02" + "ab" * 32},
        )
        assert resp.status_code == 402
        assert "x-bsv-payment-derivation-prefix" in resp.headers
        assert resp.headers["x-bsv-payment-satoshis-required"] == "100"
        assert resp.json()["code"] == "ERR_PAYMENT_REQUIRED"

    def test_full_402_flow(self):
        """Complete: auth → 402 → pay → success."""
        app = _create_app(pricing_satoshis=50)
        client = TestClient(app)
        identity_key = "02" + "ab" * 32

        # Step 1: Get 402 challenge
        resp = client.get(
            "/api/data",
            headers={"x-bsv-auth-identity-key": identity_key},
        )
        assert resp.status_code == 402
        prefix = resp.headers["x-bsv-payment-derivation-prefix"]

        # Step 2: Send payment
        payment = BSVPayment(
            derivation_prefix=prefix,
            derivation_suffix="client-suffix-123",
            transaction="bW9jay10eA==",  # mock tx
        )
        resp = client.get(
            "/api/data",
            headers={
                "x-bsv-auth-identity-key": identity_key,
                "x-bsv-payment": json.dumps(payment.to_dict()),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert resp.json()["satoshis_paid"] == 50
        assert resp.headers["x-bsv-payment-satoshis-paid"] == "50"

    def test_replay_nonce_rejected(self):
        """Same nonce cannot be used twice."""
        app = _create_app()
        client = TestClient(app)
        identity_key = "02" + "ab" * 32

        # Get nonce
        resp = client.get(
            "/api/data",
            headers={"x-bsv-auth-identity-key": identity_key},
        )
        prefix = resp.headers["x-bsv-payment-derivation-prefix"]

        # First payment succeeds
        payment = BSVPayment(
            derivation_prefix=prefix,
            derivation_suffix="suffix",
            transaction="dHg=",
        )
        headers = {
            "x-bsv-auth-identity-key": identity_key,
            "x-bsv-payment": json.dumps(payment.to_dict()),
        }
        resp = client.get("/api/data", headers=headers)
        assert resp.status_code == 200

        # Replay with same nonce fails
        resp = client.get("/api/data", headers=headers)
        assert resp.status_code == 400
        assert resp.json()["code"] == "ERR_INVALID_DERIVATION_PREFIX"

    def test_malformed_payment_header(self):
        """Invalid JSON in payment header returns 400."""
        app = _create_app()
        client = TestClient(app)
        resp = client.get(
            "/api/data",
            headers={
                "x-bsv-auth-identity-key": "02" + "ab" * 32,
                "x-bsv-payment": "not-json",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == "ERR_MALFORMED_PAYMENT"

    def test_free_request_passes_through(self):
        """Price = 0 skips payment requirement."""
        app = _create_app(pricing_satoshis=0)
        client = TestClient(app)
        resp = client.get(
            "/api/data",
            headers={"x-bsv-auth-identity-key": "02" + "ab" * 32},
        )
        assert resp.status_code == 200
        assert resp.json()["satoshis_paid"] == 0

    def test_payment_rejected(self):
        """verify_payment returning accepted=False returns 400."""
        app = _create_app(
            verify_result=PaymentResult(satoshis_paid=0, accepted=False),
        )
        client = TestClient(app)
        identity_key = "02" + "ab" * 32

        # Get nonce
        resp = client.get(
            "/api/data",
            headers={"x-bsv-auth-identity-key": identity_key},
        )
        prefix = resp.headers["x-bsv-payment-derivation-prefix"]

        # Send payment that will be rejected
        payment = BSVPayment(
            derivation_prefix=prefix,
            derivation_suffix="s",
            transaction="dHg=",
        )
        resp = client.get(
            "/api/data",
            headers={
                "x-bsv-auth-identity-key": identity_key,
                "x-bsv-payment": json.dumps(payment.to_dict()),
            },
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == "ERR_PAYMENT_REJECTED"
