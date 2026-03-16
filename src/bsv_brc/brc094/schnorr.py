"""
Schnorr proof for ECDH shared secrets (BRC-94).

The protocol proves that S = a * B (shared secret) where:
- a is the prover's private key (never revealed)
- A = a * G is the prover's public key
- B is the counterparty's public key
- S is the ECDH shared secret

Proof: (R, S', z) where:
- k = random nonce
- R = k * G
- S' = k * B
- e = SHA256(R || S' || A || B || S)
- z = k + e * a (mod n)

Verification:
- z * G == R + e * A
- z * B == S' + e * S
"""

import hashlib
import os

import coincurve

from bsv_brc.crypto.keys import SECP256K1_N


def _point_add(p1: bytes, p2: bytes) -> bytes:
    """Add two compressed public key points."""
    pub = coincurve.PublicKey(p1)
    # coincurve.PublicKey.combine requires a list of PublicKey objects
    return coincurve.PublicKey.combine_keys(
        [pub, coincurve.PublicKey(p2)]
    ).format(compressed=True)


def _scalar_mult(scalar: bytes, point: bytes) -> bytes:
    """Multiply a compressed point by a scalar."""
    pub = coincurve.PublicKey(point)
    return pub.multiply(scalar).format(compressed=True)


def _scalar_mult_g(scalar: bytes) -> bytes:
    """Multiply the generator G by a scalar (= compute public key)."""
    return coincurve.PrivateKey(scalar).public_key.format(compressed=True)


def _compute_challenge(
    R: bytes, S_prime: bytes, A: bytes, B: bytes, S: bytes
) -> int:
    """e = SHA256(R || S' || A || B || S)"""
    h = hashlib.sha256()
    h.update(R)
    h.update(S_prime)
    h.update(A)
    h.update(B)
    h.update(S)
    return int.from_bytes(h.digest(), "big") % SECP256K1_N


def generate_proof(
    prover_private_key: bytes,
    counterparty_public_key: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Generate a Schnorr proof that the prover knows the ECDH shared secret.

    Args:
        prover_private_key: 32-byte private key of the prover.
        counterparty_public_key: 33-byte compressed public key of the counterparty.

    Returns:
        Tuple of (shared_secret, R, S_prime, z) where:
        - shared_secret: 33-byte compressed ECDH shared secret
        - R: 33-byte compressed point (k * G)
        - S_prime: 33-byte compressed point (k * B)
        - z: 32-byte scalar (k + e * a mod n)
    """
    A = _scalar_mult_g(prover_private_key)
    B = counterparty_public_key
    S = _scalar_mult(prover_private_key, B)

    # Random nonce k
    k = os.urandom(32)
    # Ensure k is valid (non-zero, < n)
    k_int = int.from_bytes(k, "big") % SECP256K1_N
    if k_int == 0:
        k_int = 1
    k = k_int.to_bytes(32, "big")

    R = _scalar_mult_g(k)
    S_prime = _scalar_mult(k, B)

    e = _compute_challenge(R, S_prime, A, B, S)

    # z = k + e * a (mod n)
    a_int = int.from_bytes(prover_private_key, "big")
    z_int = (k_int + e * a_int) % SECP256K1_N
    z = z_int.to_bytes(32, "big")

    return S, R, S_prime, z


def verify_proof(
    prover_public_key: bytes,
    counterparty_public_key: bytes,
    shared_secret: bytes,
    R: bytes,
    S_prime: bytes,
    z: bytes,
) -> bool:
    """
    Verify a Schnorr proof of an ECDH shared secret.

    No private keys needed — only public keys and the proof.

    Args:
        prover_public_key: 33-byte compressed public key (A).
        counterparty_public_key: 33-byte compressed public key (B).
        shared_secret: 33-byte compressed claimed shared secret (S).
        R: 33-byte compressed point from proof.
        S_prime: 33-byte compressed point from proof.
        z: 32-byte scalar from proof.

    Returns:
        True if the proof is valid.
    """
    A = prover_public_key
    B = counterparty_public_key
    S = shared_secret

    e = _compute_challenge(R, S_prime, A, B, S)
    e_bytes = e.to_bytes(32, "big")

    # Check 1: z * G == R + e * A
    z_G = _scalar_mult_g(z)
    e_A = _scalar_mult(e_bytes, A)
    R_plus_eA = _point_add(R, e_A)
    if z_G != R_plus_eA:
        return False

    # Check 2: z * B == S' + e * S
    z_B = _scalar_mult(z, B)
    e_S = _scalar_mult(e_bytes, S)
    Sp_plus_eS = _point_add(S_prime, e_S)
    if z_B != Sp_plus_eS:
        return False

    return True
