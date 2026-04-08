"""
BRC-105 minimal server example.

A Starlette app with one paid endpoint (`/data`) that costs 100 satoshis,
and one free endpoint (`/health`).

Run:
    pip install "bsv-brc[starlette]" uvicorn
    python examples/brc105_minimal_server.py

Then in another terminal:
    python examples/brc105_client.py

⚠️  DEMO ONLY — DO NOT DEPLOY ⚠️
This example uses a fake `verify_payment` stub that accepts every payment
without actually verifying anything on-chain. In production you must wire
this up to a real BSV wallet via `wallet.internalizeAction()` (or equivalent).
The `get_identity_key` override here also bypasses BRC-103 authentication
for local testing — production code must NOT do this.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from bsv_brc.brc105 import (
    BSVPayment,
    NonceManager,
    PaymentMiddleware,
    PaymentResult,
    StaticPricing,
)


# --- handlers ---

async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def data(request: Request) -> JSONResponse:
    # PaymentMiddleware attaches the result to request.state on success.
    paid = request.state.payment.satoshis_paid
    return JSONResponse({"data": "hello, paying customer", "satoshis_paid": paid})


# --- payment plumbing (DEMO STUBS — replace in production) ---

async def fake_verify_payment(payment: BSVPayment, identity_key: str) -> PaymentResult:
    """
    DEMO ONLY. Always accepts. In production, call your BSV wallet's
    internalizeAction() with the payment's transaction and return the
    real result from the wallet.
    """
    return PaymentResult(satoshis_paid=100, accepted=True)


def fake_get_identity_key(_: Request) -> str:
    """
    DEMO ONLY. Bypasses BRC-103 auth for local testing.
    Production code must read a real identity key set by BRC-104 middleware.
    """
    return "demo-identity-key-not-for-production"


# --- app ---

app = Starlette(
    routes=[
        Route("/health", health),
        Route("/data", data),
    ],
)

app.add_middleware(
    PaymentMiddleware,
    nonce_manager=NonceManager(secret=b"demo-server-secret-change-me"),
    pricing=StaticPricing(100),  # 100 satoshis per request
    verify_payment=fake_verify_payment,
    get_identity_key=fake_get_identity_key,
    excluded_paths={"/health"},
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
