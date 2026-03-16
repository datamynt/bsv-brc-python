"""Tests for BRC-94 Schnorr proof of ECDH shared secrets."""

import os

import coincurve

from bsv_brc.brc094 import (
    generate_proof,
    verify_proof,
    create_counterparty_linkage_revelation,
    verify_counterparty_linkage,
)


def _random_keypair() -> tuple[bytes, bytes]:
    priv = os.urandom(32)
    pub = coincurve.PrivateKey(priv).public_key.format(compressed=True)
    return priv, pub


class TestSchnorrProof:
    """Core Schnorr proof generation and verification."""

    def test_valid_proof(self):
        alice_priv, alice_pub = _random_keypair()
        _, bob_pub = _random_keypair()

        S, R, S_prime, z = generate_proof(alice_priv, bob_pub)

        assert verify_proof(alice_pub, bob_pub, S, R, S_prime, z)

    def test_wrong_counterparty_fails(self):
        alice_priv, alice_pub = _random_keypair()
        _, bob_pub = _random_keypair()
        _, carol_pub = _random_keypair()

        S, R, S_prime, z = generate_proof(alice_priv, bob_pub)

        # Verify against wrong counterparty
        assert not verify_proof(alice_pub, carol_pub, S, R, S_prime, z)

    def test_wrong_prover_fails(self):
        alice_priv, alice_pub = _random_keypair()
        _, bob_pub = _random_keypair()
        _, carol_pub = _random_keypair()

        S, R, S_prime, z = generate_proof(alice_priv, bob_pub)

        # Verify with wrong prover key
        assert not verify_proof(carol_pub, bob_pub, S, R, S_prime, z)

    def test_tampered_shared_secret_fails(self):
        alice_priv, alice_pub = _random_keypair()
        _, bob_pub = _random_keypair()

        S, R, S_prime, z = generate_proof(alice_priv, bob_pub)

        # Use a different shared secret
        fake_S = coincurve.PublicKey(bob_pub).multiply(os.urandom(32)).format(
            compressed=True
        )
        assert not verify_proof(alice_pub, bob_pub, fake_S, R, S_prime, z)

    def test_ecdh_symmetry(self):
        """The shared secret should be the same regardless of who proves it."""
        alice_priv, alice_pub = _random_keypair()
        bob_priv, bob_pub = _random_keypair()

        S_alice, _, _, _ = generate_proof(alice_priv, bob_pub)
        S_bob, _, _, _ = generate_proof(bob_priv, alice_pub)

        assert S_alice == S_bob

    def test_multiple_proofs_different_nonces(self):
        """Each proof should use a different nonce (R differs)."""
        alice_priv, _ = _random_keypair()
        _, bob_pub = _random_keypair()

        _, R1, _, _ = generate_proof(alice_priv, bob_pub)
        _, R2, _, _ = generate_proof(alice_priv, bob_pub)

        assert R1 != R2  # different random nonce each time


class TestCounterpartyLinkage:
    """High-level counterparty linkage revelation."""

    def test_create_and_verify(self):
        alice_priv, _ = _random_keypair()
        _, bob_pub = _random_keypair()

        revelation = create_counterparty_linkage_revelation(alice_priv, bob_pub)

        assert revelation.type == "counterparty-revelation"
        assert verify_counterparty_linkage(revelation)

    def test_serialization_roundtrip(self):
        alice_priv, _ = _random_keypair()
        _, bob_pub = _random_keypair()

        revelation = create_counterparty_linkage_revelation(alice_priv, bob_pub)
        d = revelation.to_dict()

        assert d["type"] == "counterparty-revelation"
        assert "proof" in d
        assert "R" in d["proof"]
        assert "Sprime" in d["proof"]
        assert "z" in d["proof"]
        assert "sharedSecret" in d
