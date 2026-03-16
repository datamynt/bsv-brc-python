"""
Nonce management for BRC-105 derivation prefixes.

The derivation prefix is a random nonce that:
1. Uniquely identifies a payment challenge
2. Is cryptographically bound to the server's wallet via createNonce/verifyNonce
3. Has a TTL to prevent replay attacks

This implements the server-side nonce lifecycle. In production, the wallet's
createNonce/verifyNonce (BRC-100) handles this. This module provides a
standalone implementation for servers that don't use a full BRC-100 wallet.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field


@dataclass
class _NonceEntry:
    nonce: str
    created_at: float


class NonceManager:
    """
    Server-side nonce manager for derivation prefixes.

    Generates random nonces and tracks them with TTL for replay protection.
    For production use with a BRC-100 wallet, use the wallet's own
    createNonce/verifyNonce instead.
    """

    def __init__(
        self,
        secret: bytes,
        ttl_seconds: int = 300,
        max_entries: int = 10_000,
    ):
        """
        Args:
            secret: Server secret for HMAC-binding nonces.
            ttl_seconds: How long a nonce is valid (default 5 min).
            max_entries: Max tracked nonces before cleanup.
        """
        self._secret = secret
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._nonces: dict[str, _NonceEntry] = {}

    def create(self) -> str:
        """Generate a new derivation prefix (random + HMAC tag)."""
        self._cleanup()
        raw = os.urandom(32)
        tag = hmac.new(self._secret, raw, hashlib.sha256).digest()[:8]
        nonce = (raw + tag).hex()
        self._nonces[nonce] = _NonceEntry(nonce=nonce, created_at=time.time())
        return nonce

    def verify(self, nonce: str) -> bool:
        """
        Verify and consume a nonce (one-time use).

        Returns True if valid, False if expired/unknown/already used.
        """
        entry = self._nonces.pop(nonce, None)
        if entry is None:
            return False
        if time.time() - entry.created_at > self._ttl:
            return False
        # Verify HMAC tag
        raw = bytes.fromhex(nonce[:64])
        tag = bytes.fromhex(nonce[64:])
        expected = hmac.new(self._secret, raw, hashlib.sha256).digest()[:8]
        return hmac.compare_digest(tag, expected)

    def _cleanup(self) -> None:
        """Remove expired entries."""
        if len(self._nonces) < self._max_entries:
            return
        now = time.time()
        self._nonces = {
            k: v
            for k, v in self._nonces.items()
            if now - v.created_at <= self._ttl
        }
