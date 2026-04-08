"""
BRC-103 wallet abstraction.

BRC-103 signing requires a wallet that can derive child keys via BRC-42
and produce signatures with a BRC-43 protocol/key ID. Different users
will have different wallets — bare private keys, hardware wallets,
remote signing services, or full @bsv/sdk-style wallets.

This module defines a minimal `Wallet` Protocol (duck-typed) that the
signing layer depends on, plus a `PrivateKeyWallet` default
implementation built on `bsv.keys.PrivateKey`. Any object that
implements the four methods on the Protocol works — no inheritance
required.

The Protocol mirrors the shape of `@bsv/sdk`'s `WalletInterface`
(create_signature / verify_signature) so a future Python port of
@bsv/sdk's wallet can be passed in directly with no adapter code.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from bsv.keys import PrivateKey, PublicKey


def _invoice_number(security_level: int, protocol_id: str, key_id: str) -> str:
    """Build the BRC-42/43 invoice number used for child key derivation."""
    return f"{security_level}-{protocol_id}-{key_id}"


@runtime_checkable
class Wallet(Protocol):
    """
    Minimal wallet interface for BRC-103 signing/verification.

    Any object implementing these four methods satisfies the contract.
    See `PrivateKeyWallet` for the reference implementation.
    """

    def get_public_key(self) -> str:
        """Return this wallet's identity public key as a hex-encoded compressed point (66 chars)."""
        ...

    def create_signature(
        self,
        data: bytes,
        protocol_id: str,
        security_level: int,
        key_id: str,
        counterparty: str,
    ) -> bytes:
        """
        Sign `data` for `counterparty` under the given BRC-43 protocol/key ID.

        Args:
            data: The bytes to sign (already the full pre-image; the wallet
                hashes internally).
            protocol_id: BRC-43 protocol name, e.g. "auth message signature".
            security_level: BRC-43 security level (2 for BRC-103).
            key_id: BRC-43 key ID, e.g. "<counterparty_nonce> <sender_nonce>".
            counterparty: Counterparty identity public key as hex (compressed).

        Returns:
            DER-encoded ECDSA signature bytes.
        """
        ...

    def verify_signature(
        self,
        data: bytes,
        signature: bytes,
        protocol_id: str,
        security_level: int,
        key_id: str,
        counterparty: str,
    ) -> bool:
        """
        Verify a signature produced by `counterparty` over `data`.

        The arguments mirror `create_signature` exactly. The verifier
        passes the OTHER party's identity key as `counterparty`.
        """
        ...


class PrivateKeyWallet:
    """
    Default `Wallet` implementation backed by a single `bsv.keys.PrivateKey`.

    Suitable for servers, scripts, and tests. For production user wallets
    you will likely want to plug in a richer wallet implementation.
    """

    def __init__(self, private_key: PrivateKey):
        if not isinstance(private_key, PrivateKey):
            raise TypeError("private_key must be a bsv.keys.PrivateKey instance")
        self._private_key = private_key

    @property
    def private_key(self) -> PrivateKey:
        return self._private_key

    def get_public_key(self) -> str:
        return self._private_key.public_key().hex()

    def create_signature(
        self,
        data: bytes,
        protocol_id: str,
        security_level: int,
        key_id: str,
        counterparty: str,
    ) -> bytes:
        invoice_number = _invoice_number(security_level, protocol_id, key_id)
        counterparty_pub = PublicKey(counterparty)
        signing_key = self._private_key.derive_child(counterparty_pub, invoice_number)
        return signing_key.sign(data)

    def verify_signature(
        self,
        data: bytes,
        signature: bytes,
        protocol_id: str,
        security_level: int,
        key_id: str,
        counterparty: str,
    ) -> bool:
        invoice_number = _invoice_number(security_level, protocol_id, key_id)
        counterparty_pub = PublicKey(counterparty)
        # The counterparty signed with derive_child(our_pub, invoice_number).
        # By BRC-42 symmetry we recover the matching child public key from
        # (their_pub, our_priv, invoice_number) and verify against it.
        signing_pub = counterparty_pub.derive_child(self._private_key, invoice_number)
        try:
            return signing_pub.verify(signature, data)
        except Exception:
            return False
