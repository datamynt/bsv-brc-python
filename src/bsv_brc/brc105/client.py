"""
BRC-105 payment client.

Handles the client-side 402 flow automatically:
1. Send request
2. Receive 402 with payment challenge
3. Build and sign payment transaction
4. Re-send request with x-bsv-payment header

Usage:
    client = PaymentClient(build_payment=my_build_fn)
    response = await client.fetch("https://api.example.com/data", method="POST", body=data)
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from bsv_brc.brc105.types import BSVPayment, PaymentChallenge
from bsv_brc.brc105.challenge import parse_challenge_headers

# Type for the payment builder callback.
# Receives (identity_key_of_server, challenge) and returns BSVPayment.
# This is where you call wallet.createAction() to build the payment tx.
BuildPaymentFn = Callable[[PaymentChallenge], Awaitable[BSVPayment]]


class PaymentClient:
    """
    Client that handles BRC-105 402 Payment Required flow.

    Framework-agnostic: works with any HTTP client via the send_request callback.
    """

    def __init__(
        self,
        build_payment: BuildPaymentFn,
        max_retries: int = 1,
    ):
        """
        Args:
            build_payment: Async callback that builds a payment transaction.
                Receives a PaymentChallenge and returns a BSVPayment with
                the signed transaction.
            max_retries: Max 402 retries (default 1 = one payment attempt).
        """
        self.build_payment = build_payment
        self.max_retries = max_retries

    async def handle_402(
        self,
        response_status: int,
        response_headers: dict[str, str],
    ) -> dict[str, str] | None:
        """
        Handle a 402 response by building a payment.

        Returns extra headers to add to the retry request,
        or None if the response is not a valid 402 challenge.
        """
        if response_status != 402:
            return None

        challenge = parse_challenge_headers(response_headers)
        if challenge is None:
            return None

        payment = await self.build_payment(challenge)
        return {"x-bsv-payment": json.dumps(payment.to_dict())}
