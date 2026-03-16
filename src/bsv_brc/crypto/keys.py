"""
BRC-42/43 key derivation — shared with brc52-python.

Re-implements the core primitives needed by BRC-94 and BRC-105 so this
package has no dependency on brc52-python (they can coexist).
"""

import hashlib
import hmac

import coincurve

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def invoice_number(security_level: int, protocol: str, key_id: str) -> str:
    """BRC-43 invoice number: ``{level}-{protocol}-{key_id}``."""
    return f"{security_level}-{protocol.lower().strip()}-{key_id}"


def shared_secret(my_private_key: bytes, counterparty_public_key: bytes) -> bytes:
    """BRC-42 ECDH shared secret (33-byte compressed point)."""
    pub = coincurve.PublicKey(counterparty_public_key)
    return pub.multiply(my_private_key).format(compressed=True)


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

    pub_obj = coincurve.PublicKey(counterparty_public_key)
    derived_pub = pub_obj.add(h)

    sym_point = derived_pub.multiply(derived_priv)
    return sym_point.format(compressed=False)[1:33]


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
    priv_obj = coincurve.PrivateKey(private_key)
    my_pub = priv_obj.public_key.format(compressed=True)

    hmac_key = (
        my_pub
        if counterparty_public_key is None
        else shared_secret(private_key, counterparty_public_key)
    )

    inv = invoice_number(security_level, protocol, key_id)
    h = _hmac_sha256(hmac_key, inv)

    h_int = int.from_bytes(h, "big")
    priv_int = int.from_bytes(private_key, "big")
    derived_priv = ((priv_int + h_int) % SECP256K1_N).to_bytes(32, "big")

    derived_pub = coincurve.PrivateKey(derived_priv).public_key.format(compressed=True)
    return derived_priv, derived_pub


def public_key_from_private(private_key: bytes) -> bytes:
    """Return 33-byte compressed public key from 32-byte private key."""
    return coincurve.PrivateKey(private_key).public_key.format(compressed=True)
