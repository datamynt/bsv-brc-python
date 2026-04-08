"""Tests for BRC-103 nonce generation and validation."""

import base64

from bsv_brc.brc103 import generate_nonce, is_valid_nonce


class TestGenerateNonce:
    def test_returns_string(self):
        nonce = generate_nonce()
        assert isinstance(nonce, str)

    def test_decodes_to_32_bytes(self):
        nonce = generate_nonce()
        decoded = base64.b64decode(nonce)
        assert len(decoded) == 32

    def test_is_base64(self):
        nonce = generate_nonce()
        # Should round-trip cleanly through base64.
        base64.b64decode(nonce, validate=True)

    def test_unique(self):
        nonces = {generate_nonce() for _ in range(100)}
        # 100 random 256-bit values should all be unique.
        assert len(nonces) == 100

    def test_self_validates(self):
        for _ in range(10):
            assert is_valid_nonce(generate_nonce())


class TestIsValidNonce:
    def test_accepts_valid(self):
        valid = base64.b64encode(b"\x00" * 32).decode("ascii")
        assert is_valid_nonce(valid)

    def test_rejects_wrong_length(self):
        too_short = base64.b64encode(b"\x00" * 16).decode("ascii")
        too_long = base64.b64encode(b"\x00" * 64).decode("ascii")
        assert not is_valid_nonce(too_short)
        assert not is_valid_nonce(too_long)

    def test_rejects_non_base64(self):
        assert not is_valid_nonce("not base64 at all!!!")
        assert not is_valid_nonce("====")
        assert not is_valid_nonce("")

    def test_rejects_non_string(self):
        assert not is_valid_nonce(None)  # type: ignore[arg-type]
        assert not is_valid_nonce(123)  # type: ignore[arg-type]
        assert not is_valid_nonce(b"bytes not str")  # type: ignore[arg-type]
