"""BRC-105 type definitions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


PAYMENT_VERSION = "1.0"


@dataclass
class PaymentChallenge:
    """Server's 402 response parameters."""

    version: str = PAYMENT_VERSION
    satoshis_required: int = 0
    derivation_prefix: str = ""

    def to_headers(self) -> dict[str, str]:
        return {
            "x-bsv-payment-version": self.version,
            "x-bsv-payment-satoshis-required": str(self.satoshis_required),
            "x-bsv-payment-derivation-prefix": self.derivation_prefix,
        }


@dataclass
class BSVPayment:
    """Client's payment submission (from x-bsv-payment header)."""

    derivation_prefix: str
    derivation_suffix: str
    transaction: str  # base64-encoded AtomicBEEF

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BSVPayment:
        return cls(
            derivation_prefix=data["derivationPrefix"],
            derivation_suffix=data["derivationSuffix"],
            transaction=data["transaction"],
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "derivationPrefix": self.derivation_prefix,
            "derivationSuffix": self.derivation_suffix,
            "transaction": self.transaction,
        }


@dataclass
class PaymentResult:
    """Result of payment verification."""

    satoshis_paid: int = 0
    accepted: bool = False
    tx: str | None = None


class PricingStrategy(ABC):
    """Interface for calculating request prices."""

    @abstractmethod
    async def calculate_price(self, request: Any) -> int:
        """Return price in satoshis for the given request. 0 = free."""
        ...


class StaticPricing(PricingStrategy):
    """Fixed price for all requests."""

    def __init__(self, satoshis: int = 100):
        self._satoshis = satoshis

    async def calculate_price(self, request: Any) -> int:
        return self._satoshis
