"""Tests for AES-256-GCM with BSV SDK wire format."""

import os
import pytest
from bsv_brc.brc052 import encrypt, decrypt


class TestAESRoundTrip:
    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        plaintext = b"hello@example.com"
        assert decrypt(key, encrypt(key, plaintext)) == plaintext

    def test_empty_plaintext(self):
        key = os.urandom(32)
        assert decrypt(key, encrypt(key, b"")) == b""

    def test_large_plaintext(self):
        key = os.urandom(32)
        plaintext = os.urandom(10_000)
        assert decrypt(key, encrypt(key, plaintext)) == plaintext


class TestWireFormat:
    def test_layout_iv32_ct_tag16(self):
        key = os.urandom(32)
        plaintext = b"test"
        encrypted = encrypt(key, plaintext)
        assert len(encrypted) == 32 + len(plaintext) + 16

    def test_different_iv_each_time(self):
        key = os.urandom(32)
        a = encrypt(key, b"same")
        b = encrypt(key, b"same")
        assert a[:32] != b[:32]
        assert a != b


class TestDecryptFailures:
    def test_wrong_key(self):
        encrypted = encrypt(os.urandom(32), b"secret")
        with pytest.raises(Exception):
            decrypt(os.urandom(32), encrypted)

    def test_tampered_ciphertext(self):
        key = os.urandom(32)
        data = bytearray(encrypt(key, b"secret"))
        data[33] ^= 0xFF
        with pytest.raises(Exception):
            decrypt(key, bytes(data))

    def test_tampered_tag(self):
        key = os.urandom(32)
        data = bytearray(encrypt(key, b"secret"))
        data[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt(key, bytes(data))

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt(os.urandom(32), b"short")
