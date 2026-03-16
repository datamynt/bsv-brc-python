"""Tests for BRC-105 payment middleware and client."""

import json
import os

import pytest

from bsv_brc.brc105 import (
    PaymentChallenge,
    BSVPayment,
    PaymentResult,
    StaticPricing,
    NonceManager,
    create_challenge,
    parse_challenge_headers,
)
from bsv_brc.brc105.client import PaymentClient


class TestNonceManager:
    """Nonce creation, verification, and replay protection."""

    def setup_method(self):
        self.manager = NonceManager(secret=os.urandom(32), ttl_seconds=60)

    def test_create_and_verify(self):
        nonce = self.manager.create()
        assert isinstance(nonce, str)
        assert len(nonce) == 80  # 32 bytes raw + 8 bytes tag = 40 bytes = 80 hex chars
        assert self.manager.verify(nonce)

    def test_replay_protection(self):
        """A nonce can only be used once."""
        nonce = self.manager.create()
        assert self.manager.verify(nonce)
        assert not self.manager.verify(nonce)  # second use rejected

    def test_unknown_nonce_rejected(self):
        assert not self.manager.verify("deadbeef" * 10)

    def test_tampered_nonce_rejected(self):
        nonce = self.manager.create()
        # Flip a byte in the random part
        tampered = "ff" + nonce[2:]
        # Remove from store so we test the HMAC check path
        self.manager._nonces[tampered] = self.manager._nonces.pop(nonce)
        assert not self.manager.verify(tampered)


class TestPaymentChallenge:
    """402 challenge creation and header parsing."""

    def test_create_challenge(self):
        challenge = create_challenge("abc123", 500)
        assert challenge.satoshis_required == 500
        assert challenge.derivation_prefix == "abc123"
        assert challenge.version == "1.0"

    def test_to_headers(self):
        challenge = create_challenge("prefix", 100)
        headers = challenge.to_headers()
        assert headers["x-bsv-payment-version"] == "1.0"
        assert headers["x-bsv-payment-satoshis-required"] == "100"
        assert headers["x-bsv-payment-derivation-prefix"] == "prefix"

    def test_parse_headers_roundtrip(self):
        original = create_challenge("myprefix", 250)
        headers = original.to_headers()
        parsed = parse_challenge_headers(headers)
        assert parsed is not None
        assert parsed.satoshis_required == 250
        assert parsed.derivation_prefix == "myprefix"

    def test_parse_missing_headers(self):
        assert parse_challenge_headers({}) is None
        assert parse_challenge_headers({"x-bsv-payment-version": "1.0"}) is None


class TestBSVPayment:
    """Payment data serialization."""

    def test_from_dict(self):
        data = {
            "derivationPrefix": "abc",
            "derivationSuffix": "def",
            "transaction": "base64beef==",
        }
        payment = BSVPayment.from_dict(data)
        assert payment.derivation_prefix == "abc"
        assert payment.derivation_suffix == "def"
        assert payment.transaction == "base64beef=="

    def test_roundtrip(self):
        payment = BSVPayment(
            derivation_prefix="p",
            derivation_suffix="s",
            transaction="tx==",
        )
        d = payment.to_dict()
        restored = BSVPayment.from_dict(d)
        assert restored.derivation_prefix == payment.derivation_prefix
        assert restored.transaction == payment.transaction


class TestStaticPricing:
    """Static pricing strategy."""

    @pytest.mark.asyncio
    async def test_returns_fixed_price(self):
        pricing = StaticPricing(42)
        assert await pricing.calculate_price(None) == 42


class TestPaymentClient:
    """Client-side 402 handling."""

    @pytest.mark.asyncio
    async def test_handle_402(self):
        async def mock_build(challenge: PaymentChallenge) -> BSVPayment:
            return BSVPayment(
                derivation_prefix=challenge.derivation_prefix,
                derivation_suffix="client-suffix",
                transaction="mock-tx-base64",
            )

        client = PaymentClient(build_payment=mock_build)

        headers = create_challenge("server-prefix", 100).to_headers()
        extra = await client.handle_402(402, headers)

        assert extra is not None
        assert "x-bsv-payment" in extra
        payment = json.loads(extra["x-bsv-payment"])
        assert payment["derivationPrefix"] == "server-prefix"
        assert payment["derivationSuffix"] == "client-suffix"

    @pytest.mark.asyncio
    async def test_non_402_returns_none(self):
        client = PaymentClient(build_payment=lambda c: None)  # type: ignore
        assert await client.handle_402(200, {}) is None
        assert await client.handle_402(404, {}) is None
