"""
BRC-105 minimal client example.

Walks through the full 402 Payment Required flow against the example server:

    1. Hit /data without payment           → 402 with payment challenge
    2. Build a BSVPayment from the challenge → POST again with x-bsv-payment
    3. Server accepts                       → 200 with the response

Run the server first:
    python examples/brc105_minimal_server.py

Then in another terminal:
    python examples/brc105_client.py

⚠️  DEMO ONLY — DO NOT DEPLOY ⚠️
The `build_payment` function in this example produces a fake payment with
hardcoded values. In production you must call your BSV wallet's
`createAction()` to build a real signed transaction that pays the server's
derived output script.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from bsv_brc.brc105 import BSVPayment, PaymentChallenge, parse_challenge_headers


SERVER_URL = "http://127.0.0.1:8000"


async def fake_build_payment(challenge: PaymentChallenge) -> BSVPayment:
    """
    DEMO ONLY. Returns a hardcoded fake payment.
    In production, call wallet.createAction() with the challenge to build
    a real signed BSV transaction paying the requested amount.
    """
    return BSVPayment(
        derivation_prefix=challenge.derivation_prefix,
        derivation_suffix="demo-suffix",
        transaction="BASE64_FAKE_PAYMENT_TX_NOT_REAL",  # not a real AtomicBEEF
    )


async def main() -> None:
    async with httpx.AsyncClient() as client:
        # Step 1: hit /data with no payment
        print("→ GET /data (no payment)")
        r1 = await client.get(
            f"{SERVER_URL}/data",
            headers={"x-bsv-auth-identity-key": "demo-client-identity-key"},
        )
        print(f"  ← {r1.status_code}")

        if r1.status_code != 402:
            print(f"  unexpected response: {r1.text}")
            return

        # Step 2: parse the challenge from headers and build a fake payment
        challenge = parse_challenge_headers(dict(r1.headers))
        if challenge is None:
            print("  challenge headers missing or malformed")
            return
        print(f"  challenge: {challenge.satoshis_required} satoshis required")

        payment = await fake_build_payment(challenge)

        # Step 3: retry with the payment header
        print("→ GET /data (with payment)")
        r2 = await client.get(
            f"{SERVER_URL}/data",
            headers={
                "x-bsv-auth-identity-key": "demo-client-identity-key",
                "x-bsv-payment": json.dumps(payment.to_dict()),
            },
        )
        print(f"  ← {r2.status_code}")
        print(f"  body: {r2.json()}")
        print(f"  satoshis_paid header: {r2.headers.get('x-bsv-payment-satoshis-paid')}")


if __name__ == "__main__":
    asyncio.run(main())
