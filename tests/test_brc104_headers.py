"""Tests for BRC-104 header constants and helpers."""

from bsv_brc.brc104 import (
    BRC104_VERSION,
    WELL_KNOWN_AUTH_PATH,
    HEADER_VERSION,
    HEADER_IDENTITY_KEY,
    HEADER_NONCE,
    HEADER_YOUR_NONCE,
    HEADER_SIGNATURE,
    HEADER_REQUEST_ID,
    HEADER_MESSAGE_TYPE,
    HEADER_REQUESTED_CERTIFICATES,
    AUTH_HEADER_PREFIX,
    ALL_AUTH_HEADERS,
)
from bsv_brc.brc104.core.headers import is_auth_header


class TestConstants:
    def test_version(self):
        assert BRC104_VERSION == "1.0"

    def test_well_known_path(self):
        assert WELL_KNOWN_AUTH_PATH == "/.well-known/auth"

    def test_all_headers_lowercase(self):
        # HTTP convention; spec uses these forms.
        for h in ALL_AUTH_HEADERS:
            assert h == h.lower()

    def test_all_headers_have_prefix(self):
        for h in ALL_AUTH_HEADERS:
            assert h.startswith(AUTH_HEADER_PREFIX)

    def test_all_headers_in_set(self):
        # Sanity: every constant is in the set.
        expected = {
            HEADER_VERSION,
            HEADER_IDENTITY_KEY,
            HEADER_NONCE,
            HEADER_YOUR_NONCE,
            HEADER_SIGNATURE,
            HEADER_REQUEST_ID,
            HEADER_MESSAGE_TYPE,
            HEADER_REQUESTED_CERTIFICATES,
        }
        assert ALL_AUTH_HEADERS == expected


class TestIsAuthHeader:
    def test_recognizes_all_known(self):
        for h in ALL_AUTH_HEADERS:
            assert is_auth_header(h)

    def test_case_insensitive(self):
        assert is_auth_header("X-BSV-Auth-Identity-Key")
        assert is_auth_header("x-BSV-auth-NONCE")

    def test_rejects_non_auth(self):
        assert not is_auth_header("authorization")
        assert not is_auth_header("content-type")
        assert not is_auth_header("x-bsv-payment")  # bsv but not auth
        assert not is_auth_header("x-bsv-custom-thing")

    def test_rejects_unrelated(self):
        assert not is_auth_header("user-agent")
        assert not is_auth_header("accept")
        assert not is_auth_header("")
