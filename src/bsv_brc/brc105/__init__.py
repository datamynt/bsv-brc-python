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
from bsv_brc.brc105.middleware import PaymentMiddleware

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
