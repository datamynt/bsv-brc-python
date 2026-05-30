"""
BRC-105: HTTP Service Monetization Framework.

Implements the 402 Payment Required flow for BSV micropayments over HTTP.
Sits on top of BRC-103/104 mutual authentication.

Server-side: Starlette/ASGI middleware that challenges clients with 402.
Client-side: PaymentClient that handles 402 → pay → retry automatically.

References:
    BRC-105: https://bsv.brc.dev/payments/0105
    BRC-29:  https://bsv.brc.dev/payments/0029
    BRC-118: https://bsv.brc.dev/payments/0118
"""

from bsv_brc.brc105.types import (
    PaymentChallenge,
    BSVPayment,
    PaymentResult,
    PricingStrategy,
    StaticPricing,
)
from bsv_brc.brc105.nonce import NonceManager
from bsv_brc.brc105.challenge import create_challenge, parse_challenge_headers

# PaymentMiddleware depends on Starlette, which is an optional extra
# (`pip install "bsv-brc[starlette]"`). Import it lazily so the core 402
# primitives above remain usable without Starlette installed.
try:
    from bsv_brc.brc105.middleware import PaymentMiddleware
except ModuleNotFoundError as _exc:  # pragma: no cover - only without the extra

    class _MissingPaymentMiddleware:
        """Placeholder raising a clear error when Starlette is not installed."""

        _err = _exc

        def __init__(self, *_args, **_kwargs):
            raise ImportError(
                "PaymentMiddleware requires Starlette. "
                'Install it with: pip install "bsv-brc[starlette]"'
            ) from self._err

    PaymentMiddleware = _MissingPaymentMiddleware  # type: ignore[assignment,misc]

__all__ = [
    "PaymentChallenge",
    "BSVPayment",
    "PaymentResult",
    "PricingStrategy",
    "StaticPricing",
    "NonceManager",
    "create_challenge",
    "parse_challenge_headers",
    "PaymentMiddleware",
]
