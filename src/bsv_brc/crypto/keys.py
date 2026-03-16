"""
BRC-42/43 key derivation using the official BSV SDK (py-sdk).

Provides ECDH shared secrets, symmetric key derivation, and signing key
derivation — the building blocks for BRC-52 certificates, BRC-94 proofs,
and BRC-105 micropayments.
"""

import hashlib
import hmac

from bsv import PrivateKey, PublicKey
from bsv.curve import curve, curve_multiply, curve_add

SECP256K1_N = curve.n


def invoice_number(security_level: int, protocol: str, key_id: str) -> str:
    """BRC-43 invoice number: ``{level}-{protocol}-{key_id}``."""
    return f"{security_level}-{protocol.lower().strip()}-{key_id}"


def shared_secret(my_private_key: bytes, counterparty_public_key: bytes) -> bytes:
    """BRC-42 ECDH shared secret (33-byte compressed point)."""
    priv = PrivateKey(my_private_key)
    pub = PublicKey(counterparty_public_key)
    return pub.derive_shared_secret(priv)


def _hmac_sha256(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def derive_symmetric_key(
    my_private_key: bytes,
    counterparty_public_key: bytes,
    security_level: int,
    protocol: str,
    key_id: str,
) -> bytes:
    """
    BRC-43 symmetric key derivation.

    Returns 32-byte key (x-coordinate of derived ECDH point).
    """
    inv = invoice_number(security_level, protocol, key_id)
    ss = shared_secret(my_private_key, counterparty_public_key)
    h = _hmac_sha256(ss, inv)

    h_int = int.from_bytes(h, "big")
    priv_int = int.from_bytes(my_private_key, "big")
    derived_priv = ((priv_int + h_int) % SECP256K1_N).to_bytes(32, "big")

    # Derive counterparty public key: pub + h*G
    pub = PublicKey(counterparty_public_key)
    h_point = curve_multiply(h_int, curve.g)
    derived_pub_point = curve_add(pub.point(), h_point)
    derived_pub = PublicKey(derived_pub_point)

    # Symmetric key = x-coord of (derived_priv * derived_pub)
    sym_point = derived_pub.derive_shared_secret(PrivateKey(derived_priv))
    # derive_shared_secret returns 33-byte compressed; we need x-coordinate
    # Decompress to get x: parse the 33-byte compressed point
    sym_pub = PublicKey(sym_point)
    x, _ = sym_pub.point()
    return x.to_bytes(32, "big")


def derive_signing_key(
    private_key: bytes,
    security_level: int,
    protocol: str,
    key_id: str,
    counterparty_public_key: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    BRC-43 signing key derivation.

    When counterparty is None ("anyone" mode), uses own pubkey as HMAC key.
    Returns (derived_private_key, derived_public_key).
    """
    priv = PrivateKey(private_key)
    my_pub = priv.public_key().serialize()

    hmac_key = (
        my_pub
        if counterparty_public_key is None
        else shared_secret(private_key, counterparty_public_key)
    )

    inv = invoice_number(security_level, protocol, key_id)
    h = _hmac_sha256(hmac_key, inv)

    h_int = int.from_bytes(h, "big")
    priv_int = int.from_bytes(private_key, "big")
    derived_priv_int = (priv_int + h_int) % SECP256K1_N
    derived_priv = derived_priv_int.to_bytes(32, "big")

    derived_pub = PrivateKey(derived_priv).public_key().serialize()
    return derived_priv, derived_pub


def public_key_from_private(private_key: bytes) -> bytes:
    """Return 33-byte compressed public key from 32-byte private key."""
    return PrivateKey(private_key).public_key().serialize()
