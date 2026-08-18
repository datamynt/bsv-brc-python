"""Pinned cross-implementation vectors for BRC-138 (vs the reference @bsv/auth).

These vectors were captured and CERTIFIED against the canonical TypeScript
implementation (@bsv/auth 0.1.3 + @bsv/sdk, see examples/brc138_interop/):

- The Python-created proofs below were submitted to Node's verifyAuthProof
  and accepted (valid: true), proving our canonical encoding, BRC-42/43 key
  derivation and DER signature format are byte-compatible with @bsv/auth.
- The Node-created proofs below were produced by Node's createAuthProof and
  are verified by our verify_auth_proof in this file.

The clock is injected so the pinned proofs (whose expiry is in the past by
wall-clock time) still satisfy the freshness checks deterministically.
"""

from __future__ import annotations

import pytest

from bsv_brc.brc138 import AuthProof, verify_auth_proof

CLIENT_PRIV = "524c969962c3128365f5c147cea31c8cad0bad2b745020c0ad42f4d7a1785b2e"
SERVER_PRIV = "9777da3f30df19f2c1cd61420e9688e673205dd02bb4738291eaceac5eecdcf9"
CLIENT_PUB = "02eea1cc2de56a6f05ec3cb0eab671fe1c7b08aa8c58380342e75cd98c8e231b3c"

# Python-created, bodyless login proof — Node's verifyAuthProof returned
# {"valid": true, "identityKey": CLIENT_PUB} at capture time.
PY_LOGIN_PROOF = {
    "data": {
        "action": "login",
        "identityKey": CLIENT_PUB,
        "expiresAt": 1787015583918,
        "nonce": "eHbOz00W8pvtWMWSgazt+gPjNuefyQrRo5wUmau2A54=",
    },
    "signature": [
        48, 68, 2, 32, 116, 191, 100, 100, 111, 213, 251, 149, 185, 72, 140, 129,
        177, 51, 12, 130, 59, 36, 31, 186, 188, 27, 176, 38, 20, 37, 106, 168, 244,
        247, 144, 157, 2, 32, 37, 71, 24, 233, 202, 233, 142, 45, 254, 68, 81, 8,
        234, 156, 49, 13, 3, 95, 205, 11, 165, 79, 78, 198, 253, 226, 46, 39, 39,
        28, 28, 21,
    ],
}

# Python-created proof with a bound payload — Node accepted it too.
PY_UPDATE_PROOF = {
    "data": {
        "action": "updateProfile",
        "identityKey": CLIENT_PUB,
        "expiresAt": 1787015583918,
        "nonce": "azg/aTd+E9FKWidUbbZwLJNg4HkZLkZD+cvEo6J59D0=",
    },
    "signature": [
        48, 69, 2, 33, 0, 133, 205, 54, 23, 194, 80, 3, 92, 97, 245, 56, 125, 207,
        198, 148, 22, 24, 218, 11, 12, 64, 77, 54, 140, 150, 192, 243, 155, 173,
        113, 25, 147, 2, 32, 7, 149, 20, 4, 249, 189, 130, 60, 63, 182, 56, 210, 6,
        66, 214, 6, 135, 58, 236, 188, 43, 202, 58, 13, 199, 218, 107, 104, 42, 82,
        91, 94,
    ],
}
PY_UPDATE_PAYLOAD = b'{"username":"alice","role":"admin"}'

# Node-created, bodyless login proof — verifyAuthProof produced this.
NODE_LOGIN_DATA = {
    "action": "login",
    "identityKey": CLIENT_PUB,
    "expiresAt": 1787015584409,
    "nonce": "0vHr0SotrdS/bDshHoP9Nz7ufNk1ywafM3GSpfOO9dM=",
}
NODE_LOGIN_SIG = [
    48, 69, 2, 33, 0, 199, 103, 75, 212, 27, 82, 28, 147, 56, 32, 37, 75, 37, 173,
    151, 35, 71, 239, 254, 215, 246, 119, 128, 199, 48, 157, 61, 48, 137, 244, 175,
    169, 2, 32, 28, 31, 245, 12, 230, 95, 152, 60, 148, 163, 131, 150, 130, 32, 28,
    41, 219, 179, 91, 146, 126, 67, 10, 69, 56, 96, 72, 53, 107, 38, 217, 113,
]

# Node-created proof with a bound binary payload.
NODE_TRANSCRIBE_DATA = {
    "action": "transcribe",
    "identityKey": CLIENT_PUB,
    "expiresAt": 1787015584589,
    "nonce": "NUrXFgXBHGL7LZM5i9VzNZxFhCTmdbjE2F+aMzExtQ0=",
}
NODE_TRANSCRIBE_SIG = [
    48, 68, 2, 32, 87, 245, 119, 164, 197, 20, 214, 162, 115, 224, 192, 20, 96,
    140, 236, 66, 91, 202, 53, 210, 50, 73, 149, 225, 224, 220, 7, 161, 10, 216,
    35, 116, 2, 32, 127, 167, 235, 232, 87, 164, 7, 59, 200, 181, 165, 32, 36, 180,
    124, 31, 63, 97, 169, 90, 230, 50, 54, 44, 29, 155, 53, 156, 63, 231, 245, 218,
]
NODE_TRANSCRIBE_PAYLOAD = b"\x00\x01\xff raw binary body"


def _verify(data, sig, action, payload=None, expires_at=None):
    proof = AuthProof.from_dict(
        {"data": data, "signature": list(sig)}
    )
    # Inject a clock just inside the proof's own validity window.
    now_ms = (expires_at or data["expiresAt"]) - 1_000
    return verify_auth_proof(
        SERVER_PRIV,
        proof,
        action,
        single_use_store=None,
        payload=payload,
        now_ms=now_ms,
    )


class TestPinnedPythonProofs:
    """Python-created proofs the reference @bsv/auth verified at capture time."""

    def test_python_login_accepted_by_node_reference(self):
        assert _verify(PY_LOGIN_PROOF["data"], PY_LOGIN_PROOF["signature"], "login") == CLIENT_PUB

    def test_python_bound_payload_accepted_by_node_reference(self):
        identity = _verify(
            PY_UPDATE_PROOF["data"],
            PY_UPDATE_PROOF["signature"],
            "updateProfile",
            payload=PY_UPDATE_PAYLOAD,
        )
        assert identity == CLIENT_PUB


class TestPinnedNodeProofs:
    """Node-created proofs our Python implementation must verify."""

    def test_node_login_verified_by_python(self):
        assert _verify(NODE_LOGIN_DATA, NODE_LOGIN_SIG, "login") == CLIENT_PUB

    def test_node_bound_payload_verified_by_python(self):
        identity = _verify(
            NODE_TRANSCRIBE_DATA,
            NODE_TRANSCRIBE_SIG,
            "transcribe",
            payload=NODE_TRANSCRIBE_PAYLOAD,
        )
        assert identity == CLIENT_PUB

    def test_node_proof_with_wrong_payload_fails(self):
        with pytest.raises(Exception):
            _verify(
                NODE_TRANSCRIBE_DATA,
                NODE_TRANSCRIBE_SIG,
                "transcribe",
                payload=b"tampered",
            )
