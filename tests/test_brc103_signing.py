"""
Tests for BRC-103 message signing and verification.

These tests round-trip a sign/verify between two PrivateKeyWallets
playing the roles of client (Alice) and server (Bob), using the same
key_id format that py-middleware uses on the wire.
"""

import pytest
from bsv.keys import PrivateKey

from bsv_brc.brc103 import (
    AUTH_PROTOCOL_ID,
    AUTH_SECURITY_LEVEL,
    PrivateKeyWallet,
    Wallet,
    build_key_id,
    generate_nonce,
    sign_message,
    verify_message,
)


@pytest.fixture
def alice() -> PrivateKeyWallet:
    return PrivateKeyWallet(PrivateKey.from_hex("11" * 32))


@pytest.fixture
def bob() -> PrivateKeyWallet:
    return PrivateKeyWallet(PrivateKey.from_hex("22" * 32))


class TestConstants:
    def test_protocol_id(self):
        # Must NOT be "authrite message signature" — see signing.py docstring.
        assert AUTH_PROTOCOL_ID == "auth message signature"

    def test_security_level(self):
        assert AUTH_SECURITY_LEVEL == 2

    def test_build_key_id(self):
        assert build_key_id("aaa", "bbb") == "aaa bbb"


class TestPrivateKeyWallet:
    def test_get_public_key_is_compressed_hex(self, alice: PrivateKeyWallet):
        pub = alice.get_public_key()
        assert isinstance(pub, str)
        assert len(pub) == 66  # 33 bytes hex
        assert pub[:2] in ("02", "03")

    def test_protocol_conformance(self, alice: PrivateKeyWallet):
        assert isinstance(alice, Wallet)

    def test_rejects_non_private_key(self):
        with pytest.raises(TypeError):
            PrivateKeyWallet("not a key")  # type: ignore[arg-type]


class TestSignVerifyRoundTrip:
    def test_round_trip(self, alice: PrivateKeyWallet, bob: PrivateKeyWallet):
        payload = b"hello bob, this is alice"
        alice_nonce = generate_nonce()
        bob_nonce = generate_nonce()

        # Alice signs to Bob. From Alice's perspective:
        #   counterparty = Bob, counterparty_nonce = Bob's, sender_nonce = Alice's
        sig = sign_message(
            wallet=alice,
            payload=payload,
            counterparty_identity_key=bob.get_public_key(),
            counterparty_nonce=bob_nonce,
            sender_nonce=alice_nonce,
        )
        assert isinstance(sig, bytes) and len(sig) > 0

        # Bob verifies. The key_id on the wire is what Alice built:
        # "<bob_nonce> <alice_nonce>". Bob passes it through verbatim.
        wire_key_id = build_key_id(bob_nonce, alice_nonce)
        assert verify_message(
            wallet=bob,
            payload=payload,
            signature=sig,
            counterparty_identity_key=alice.get_public_key(),
            key_id=wire_key_id,
        )

    def test_wrong_payload_fails(self, alice: PrivateKeyWallet, bob: PrivateKeyWallet):
        payload = b"original"
        alice_nonce = generate_nonce()
        bob_nonce = generate_nonce()
        sig = sign_message(
            alice, payload, bob.get_public_key(), bob_nonce, alice_nonce
        )
        assert not verify_message(
            bob,
            b"tampered",
            sig,
            alice.get_public_key(),
            build_key_id(bob_nonce, alice_nonce),
        )

    def test_wrong_counterparty_fails(
        self, alice: PrivateKeyWallet, bob: PrivateKeyWallet
    ):
        eve = PrivateKeyWallet(PrivateKey.from_hex("33" * 32))
        payload = b"for bob only"
        alice_nonce = generate_nonce()
        bob_nonce = generate_nonce()
        sig = sign_message(
            alice, payload, bob.get_public_key(), bob_nonce, alice_nonce
        )
        # Eve cannot verify — the derived key chain depends on Bob's priv key.
        assert not verify_message(
            eve,
            payload,
            sig,
            alice.get_public_key(),
            build_key_id(bob_nonce, alice_nonce),
        )

    def test_wrong_key_id_fails(self, alice: PrivateKeyWallet, bob: PrivateKeyWallet):
        payload = b"x"
        alice_nonce = generate_nonce()
        bob_nonce = generate_nonce()
        sig = sign_message(
            alice, payload, bob.get_public_key(), bob_nonce, alice_nonce
        )
        # Swap nonce order — must fail.
        assert not verify_message(
            bob,
            payload,
            sig,
            alice.get_public_key(),
            build_key_id(alice_nonce, bob_nonce),
        )

    def test_garbage_signature_returns_false(
        self, alice: PrivateKeyWallet, bob: PrivateKeyWallet
    ):
        # Should not raise — wallet swallows decode errors and returns False.
        assert not verify_message(
            bob,
            b"payload",
            b"\x00\x01\x02",
            alice.get_public_key(),
            build_key_id("a", "b"),
        )
