"""Tests for BRC-42/43 key derivation."""

import os
import coincurve
from bsv_brc.crypto import keys


def make_keypair():
    priv = os.urandom(32)
    pub = coincurve.PrivateKey(priv).public_key.format(compressed=True)
    return priv, pub


class TestECDHSharedSecret:
    def test_symmetry(self):
        """certPriv * subjectPub == subjectPriv * certPub"""
        priv_a, pub_a = make_keypair()
        priv_b, pub_b = make_keypair()

        assert keys.shared_secret(priv_a, pub_b) == keys.shared_secret(priv_b, pub_a)

    def test_returns_33_bytes(self):
        priv_a, pub_a = make_keypair()
        priv_b, pub_b = make_keypair()
        ss = keys.shared_secret(priv_a, pub_b)
        assert len(ss) == 33
        assert ss[0] in (2, 3)

    def test_different_pairs_different_secrets(self):
        priv_a, pub_a = make_keypair()
        _, pub_b = make_keypair()
        _, pub_c = make_keypair()
        assert keys.shared_secret(priv_a, pub_b) != keys.shared_secret(priv_a, pub_c)


class TestInvoiceNumber:
    def test_format(self):
        assert keys.invoice_number(2, "My Protocol", "key1") == "2-my protocol-key1"

    def test_strips_whitespace(self):
        assert keys.invoice_number(1, "  foo  ", "bar") == "1-foo-bar"


class TestDeriveSymmetricKey:
    def test_symmetry(self):
        """Both parties derive the same 32-byte symmetric key."""
        priv_a, pub_a = make_keypair()
        priv_b, pub_b = make_keypair()

        key_a = keys.derive_symmetric_key(priv_a, pub_b, 2, "test", "field1")
        key_b = keys.derive_symmetric_key(priv_b, pub_a, 2, "test", "field1")

        assert key_a == key_b
        assert len(key_a) == 32

    def test_different_key_ids_different_keys(self):
        priv_a, pub_a = make_keypair()
        _, pub_b = make_keypair()

        key1 = keys.derive_symmetric_key(priv_a, pub_b, 2, "test", "email")
        key2 = keys.derive_symmetric_key(priv_a, pub_b, 2, "test", "name")
        assert key1 != key2

    def test_different_protocols_different_keys(self):
        priv_a, pub_a = make_keypair()
        _, pub_b = make_keypair()

        key1 = keys.derive_symmetric_key(priv_a, pub_b, 2, "protocol-a", "id")
        key2 = keys.derive_symmetric_key(priv_a, pub_b, 2, "protocol-b", "id")
        assert key1 != key2


class TestDeriveSigningKey:
    def test_anyone_mode(self):
        """Counterparty=None uses own pubkey as HMAC key."""
        priv, pub = make_keypair()
        derived_priv, derived_pub = keys.derive_signing_key(
            priv, 2, "certificate signature", "test"
        )
        assert len(derived_priv) == 32
        assert len(derived_pub) == 33
        assert derived_priv != priv

    def test_derived_key_is_valid(self):
        priv, _ = make_keypair()
        derived_priv, derived_pub = keys.derive_signing_key(
            priv, 2, "test", "key1"
        )
        expected_pub = coincurve.PrivateKey(derived_priv).public_key.format(compressed=True)
        assert derived_pub == expected_pub


class TestPublicKeyFromPrivate:
    def test_compressed_format(self):
        priv = os.urandom(32)
        pub = keys.public_key_from_private(priv)
        assert len(pub) == 33
        assert pub[0] in (2, 3)
