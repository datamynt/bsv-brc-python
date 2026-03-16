"""
BRC-105 payment challenge creation and parsing.

Handles the 402 response generation (server-side) and parsing (client-side).
"""

from __future__ import annotations

from bsv_brc.brc105.types import PaymentChallenge, PAYMENT_VERSION


def create_challenge(
    derivation_prefix: str,
    satoshis_required: int,
) -> PaymentChallenge:
    """Create a 402 payment challenge for the client."""
    return PaymentChallenge(
        version=PAYMENT_VERSION,
        satoshis_required=satoshis_required,
        derivation_prefix=derivation_prefix,
    )


def parse_challenge_headers(headers: dict[str, str]) -> PaymentChallenge | None:
    """
    Parse 402 response headers into a PaymentChallenge.

    Client-side: extracts payment requirements from a 402 response.
    Returns None if headers don't contain payment challenge data.
    """
    version = headers.get("x-bsv-payment-version")
    satoshis = headers.get("x-bsv-payment-satoshis-required")
    prefix = headers.get("x-bsv-payment-derivation-prefix")

    if not all([version, satoshis, prefix]):
        return None

    try:
        return PaymentChallenge(
            version=version,  # type: ignore[arg-type]
            satoshis_required=int(satoshis),  # type: ignore[arg-type]
            derivation_prefix=prefix,  # type: ignore[arg-type]
        )
    except (ValueError, TypeError):
        return None
