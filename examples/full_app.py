"""
Full BRC app example — auth + payments + an overlay topic, no fakes.

Unlike ``brc105_minimal_server.py`` (which stubs out auth and payment),
this wires the real pieces together with :func:`bsv_brc.build_brc_app`:

- BRC-103/104 mutual auth terminates at ``POST /.well-known/auth``.
- BRC-105 payments are settled through the server's real wallet via
  ``wallet.internalize_action`` (the default verifier) — no stub.
- A BRC-22 overlay topic (``tm_demo``) accepts transaction submissions
  at ``POST /submit`` and admits every output 0.

Run:
    pip install "bsv-brc[starlette]" uvicorn
    python examples/full_app.py

In production, load the server identity from a persisted key rather than
generating a fresh one on boot, and pass a stable ``nonce_secret`` so
outstanding 402 challenges survive a restart.

References:
    BRC-22:  https://bsv.brc.dev/overlays/0022
    BRC-29:  https://bsv.brc.dev/payments/0029
    BRC-105: https://bsv.brc.dev/payments/0105
"""

from __future__ import annotations

import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from bsv.keys import PrivateKey
from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions
from bsv.wallet.wallet_impl import ProtoWallet

from bsv_brc import (
    PathPricing,
    TopicEngine,
    TopicManager,
    build_brc_app,
    get_identity,
    get_payment,
)
from bsv_brc.brc22.adapters.asgi import make_submit_route


# --- the server's identity ----------------------------------------------
# Load a persisted key in production; this generates one per boot.
SERVER_WALLET = ProtoWallet(PrivateKey())


# --- a BRC-22 overlay topic ---------------------------------------------


class DemoTopicManager(TopicManager):
    """Admits output 0 of every submitted transaction into ``tm_demo``."""

    def identify_admissible_outputs(self, beef: bytes, previous_coins):
        return AdmittanceInstructions(outputs_to_admit=[0], coins_to_retain=[])

    def get_documentation(self) -> str:
        return "Demo topic: admits output 0 of every transaction."


topic_engine = TopicEngine({"tm_demo": DemoTopicManager()})


# --- application handlers ------------------------------------------------


async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def whoami(request: Request) -> JSONResponse:
    # Identity is set by AuthMiddleware after a verified BRC-104 request.
    return JSONResponse({"identity_key": get_identity(request)})


async def premium(request: Request) -> JSONResponse:
    payment = get_payment(request)
    return JSONResponse(
        {
            "data": "hello, paying customer",
            "satoshis_paid": payment.satoshis_paid if payment else 0,
            "identity_key": get_identity(request),
        }
    )


inner = Starlette(
    routes=[
        Route("/health", health),
        Route("/whoami", whoami),
        Route("/premium", premium),
        # The BRC-22 submission endpoint for the tm_demo topic.
        make_submit_route(topic_engine, "/submit"),
    ]
)


# --- compose auth + payments around the app -----------------------------

app = build_brc_app(
    inner,
    wallet=SERVER_WALLET,
    # /premium costs 100 sats; everything else is free (auth still required).
    pricing=PathPricing({"/premium": 100}, default=0),
    # A stable secret in production; random here so the example self-runs.
    nonce_secret=os.environ.get("NONCE_SECRET", "").encode() or None,
    # Health and the overlay submit endpoint should not require payment.
    excluded_paths={"/health", "/submit", "/.well-known/auth"},
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
