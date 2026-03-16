"""
BRC-105 Starlette/ASGI middleware for 402 Payment Required.

Drop-in middleware for any Starlette/FastHTML app. Equivalent to
@bsv/payment-express-middleware but for Python.

Usage:
    from bsv_brc.brc105 import PaymentMiddleware, StaticPricing

    app.add_middleware(
        PaymentMiddleware,
        nonce_manager=nonce_manager,
        pricing=StaticPricing(100),
        verify_payment=my_verify_fn,
    )
"""

from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from bsv_brc.brc105.types import (
    BSVPayment,
    PaymentResult,
    PricingStrategy,
    PAYMENT_VERSION,
)
from bsv_brc.brc105.nonce import NonceManager
from bsv_brc.brc105.challenge import create_challenge

logger = logging.getLogger(__name__)

# Type for the payment verification callback
VerifyPaymentFn = Callable[[BSVPayment, str], Awaitable[PaymentResult]]


class PaymentMiddleware(BaseHTTPMiddleware):
    """
    BRC-105 payment middleware for Starlette.

    Intercepts requests, checks if payment is required, and either:
    - Returns 402 with payment challenge headers
    - Verifies submitted payment and passes through
    - Passes through free requests unchanged

    Args:
        app: The ASGI application.
        nonce_manager: NonceManager for derivation prefix lifecycle.
        pricing: PricingStrategy to calculate request price.
        verify_payment: Async callback to verify and internalize a payment.
            Receives (BSVPayment, sender_identity_key) and returns PaymentResult.
            This is where you call wallet.internalizeAction() or equivalent.
        get_identity_key: Optional callable to extract sender identity key from request.
            Defaults to reading x-bsv-auth-identity-key header.
        excluded_paths: Paths that skip payment (e.g., health checks).
    """

    def __init__(
        self,
        app: Any,
        *,
        nonce_manager: NonceManager,
        pricing: PricingStrategy,
        verify_payment: VerifyPaymentFn,
        get_identity_key: Callable[[Request], str | None] | None = None,
        excluded_paths: set[str] | None = None,
    ):
        super().__init__(app)
        self.nonce_manager = nonce_manager
        self.pricing = pricing
        self.verify_payment = verify_payment
        self.get_identity_key = get_identity_key or _default_get_identity_key
        self.excluded_paths = excluded_paths or {"/health", "/.well-known/auth"}

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        # Skip excluded paths
        if request.url.path in self.excluded_paths:
            return await call_next(request)

        # Get sender identity key (from BRC-103/104 auth)
        identity_key = self.get_identity_key(request)
        if identity_key is None:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "code": "ERR_AUTH_REQUIRED",
                    "description": "BRC-103 authentication required before payment.",
                },
            )

        # Calculate price
        try:
            price = await self.pricing.calculate_price(request)
        except Exception:
            logger.exception("Error calculating price")
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "code": "ERR_PAYMENT_INTERNAL",
                    "description": "Error calculating payment required.",
                },
            )

        # Free request
        if price == 0:
            request.state.payment = PaymentResult(satoshis_paid=0, accepted=True)
            return await call_next(request)

        # Check for payment header
        payment_header = request.headers.get("x-bsv-payment")
        if payment_header is None:
            # Return 402 challenge
            prefix = self.nonce_manager.create()
            challenge = create_challenge(prefix, price)
            return JSONResponse(
                status_code=402,
                content={
                    "status": "error",
                    "code": "ERR_PAYMENT_REQUIRED",
                    "satoshisRequired": price,
                    "description": "A BSV payment is required. Provide the X-BSV-Payment header.",
                },
                headers=challenge.to_headers(),
            )

        # Parse payment
        try:
            payment_data = BSVPayment.from_dict(json.loads(payment_header))
        except (json.JSONDecodeError, KeyError, TypeError):
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "code": "ERR_MALFORMED_PAYMENT",
                    "description": "The X-BSV-Payment header is not valid JSON.",
                },
            )

        # Verify nonce
        if not self.nonce_manager.verify(payment_data.derivation_prefix):
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "code": "ERR_INVALID_DERIVATION_PREFIX",
                    "description": "The derivation prefix is invalid or expired.",
                },
            )

        # Verify and internalize payment
        try:
            result = await self.verify_payment(payment_data, identity_key)
        except Exception as exc:
            logger.exception("Payment verification failed")
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "code": "ERR_PAYMENT_FAILED",
                    "description": str(exc),
                },
            )

        if not result.accepted:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "code": "ERR_PAYMENT_REJECTED",
                    "description": "Payment was not accepted.",
                },
            )

        # Payment accepted — attach result and continue
        request.state.payment = result
        response = await call_next(request)
        response.headers["x-bsv-payment-satoshis-paid"] = str(result.satoshis_paid)
        return response


def _default_get_identity_key(request: Request) -> str | None:
    """Extract identity key from BRC-104 auth header."""
    return request.headers.get("x-bsv-auth-identity-key")
