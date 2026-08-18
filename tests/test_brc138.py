"""Tests for BRC-138 single-use signed proofs."""

from __future__ import annotations

import json
import time

import pytest
from bsv import PrivateKey

from bsv_brc import brc138
from bsv_brc.brc138 import (
    AuthProof,
    AuthProofData,
    AuthProofError,
    DEFAULT_CLOCK_SKEW_MS,
    DEFAULT_PROTOCOL,
    DEFAULT_VALIDITY_WINDOW_MS,
    MemorySingleUseStore,
    SqliteSingleUseStore,
    check_auth_proof_data,
    create_auth_proof,
    generate_nonce,
    normalize_body,
    verify_auth_proof,
)
from bsv_brc.crypto.keys import public_key_from_private


def _random_key() -> bytes:
    return PrivateKey().serialize()


@pytest.fixture
def keys():
    client_priv = _random_key()
    server_priv = _random_key()
    return {
        "client_priv": client_priv,
        "server_priv": server_priv,
        "client_pub": public_key_from_private(client_priv).hex(),
        "server_pub": public_key_from_private(server_priv).hex(),
    }


NOW = int(time.time() * 1000)


def _verify(keys, proof, expected_action="login", **kwargs):
    store = kwargs.pop("store", MemorySingleUseStore())
    now = kwargs.pop("now_ms", NOW + 1_000)
    return verify_auth_proof(
        keys["server_priv"],
        proof,
        expected_action,
        single_use_store=store,
        now_ms=now,
        **kwargs,
    )


class TestCreateAndVerify:
    def test_round_trip(self, keys):
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        assert proof.data.action == "login"
        assert proof.data.identity_key == keys["client_pub"]
        assert proof.data.expires_at == NOW + DEFAULT_VALIDITY_WINDOW_MS
        assert len(proof.data.nonce) > 0
        assert isinstance(proof.signature, bytes) and len(proof.signature) > 0

        identity = _verify(keys, proof)
        assert identity == keys["client_pub"]

    def test_wire_dict_round_trip(self, keys):
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        wire = proof.to_dict()
        assert set(wire) == {"data", "signature"}
        assert isinstance(wire["signature"], list)
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in wire["signature"])

        # dict input works; hex-string signature input works too
        identity = _verify(keys, wire)
        assert identity == keys["client_pub"]
        wire_hex = {"data": wire["data"], "signature": proof.signature.hex()}
        assert _verify(keys, wire_hex) == keys["client_pub"]

    def test_explicit_nonce_expiry(self, keys):
        proof = create_auth_proof(
            keys["client_priv"],
            keys["server_pub"],
            "login",
            nonce="AAAA",
            expires_at=NOW + 60_000,
            now_ms=NOW,
        )
        assert proof.data.nonce == "AAAA"
        assert proof.data.expires_at == NOW + 60_000
        assert _verify(keys, proof, now_ms=NOW + 59_000) == keys["client_pub"]

    def test_signature_is_per_nonce_key(self, keys):
        # keyID = nonce, so two proofs with different nonces use different keys.
        p1 = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        p2 = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        assert p1.signature != p2.signature

    def test_hex_private_key_input(self, keys):
        proof = create_auth_proof(
            keys["client_priv"].hex(),
            keys["server_pub"],
            "login",
            now_ms=NOW,
        )
        assert _verify(keys, proof) == keys["client_pub"]


class TestPayloadBinding:
    def test_body_binding_string(self, keys):
        proof = create_auth_proof(
            keys["client_priv"],
            keys["server_pub"],
            "update_profile",
            payload='{"username":"alice"}',
            now_ms=NOW,
        )
        # correct payload verifies
        assert (
            _verify(keys, proof, expected_action="update_profile", payload='{"username":"alice"}')
            == keys["client_pub"]
        )
        # tampered payload fails
        with pytest.raises(AuthProofError, match="invalid signature"):
            _verify(
                keys,
                proof,
                expected_action="update_profile",
                payload='{"username":"bob"}',
            )
        # missing payload fails (proof bound one)
        with pytest.raises(AuthProofError, match="invalid signature"):
            _verify(keys, proof, expected_action="update_profile")

    def test_body_binding_bytes_and_json(self, keys):
        binary = b"\x00\x01\xff\nbody-with-newlines"
        proof = create_auth_proof(
            keys["client_priv"],
            keys["server_pub"],
            "transcribe",
            payload=binary,
            now_ms=NOW,
        )
        assert (
            _verify(keys, proof, expected_action="transcribe", payload=binary)
            == keys["client_pub"]
        )
        with pytest.raises(AuthProofError, match="invalid signature"):
            _verify(
                keys,
                proof,
                expected_action="transcribe",
                payload=binary + b"x",
            )

        obj = {"prompt": "banana", "n": 2}
        proof2 = create_auth_proof(
            keys["client_priv"],
            keys["server_pub"],
            "generate",
            payload=obj,
            now_ms=NOW,
        )
        # JSON objects are normalized to compact JSON on both sides.
        assert normalize_body(obj) == b'{"prompt":"banana","n":2}'
        assert (
            _verify(keys, proof2, expected_action="generate", payload=obj)
            == keys["client_pub"]
        )
        # The verifier must bind the raw bytes received — a re-serialized
        # object with different spacing fails.
        with pytest.raises(AuthProofError, match="invalid signature"):
            _verify(
                keys,
                proof2,
                expected_action="generate",
                payload='{"prompt": "banana", "n": 2}',
            )

    def test_empty_body_distinct_from_no_body(self, keys):
        bound = create_auth_proof(
            keys["client_priv"],
            keys["server_pub"],
            "login",
            payload=b"",
            now_ms=NOW,
        )
        unbound = create_auth_proof(
            keys["client_priv"],
            keys["server_pub"],
            "login",
            now_ms=NOW,
        )
        assert bound.signature != unbound.signature
        # verifying the empty-bound proof without a payload fails
        with pytest.raises(AuthProofError, match="invalid signature"):
            _verify(keys, bound)


class TestChecks:
    def test_action_mismatch(self, keys):
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        with pytest.raises(AuthProofError, match="action mismatch"):
            _verify(keys, proof, expected_action="delete")

    def test_expired(self, keys):
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        with pytest.raises(AuthProofError, match="expired"):
            _verify(keys, proof, now_ms=proof.data.expires_at)

    def test_minted_too_far_in_future(self, keys):
        proof = create_auth_proof(
            keys["client_priv"],
            keys["server_pub"],
            "login",
            expires_at=NOW + 60 * 60_000,  # 1h validity
            now_ms=NOW,
        )
        with pytest.raises(AuthProofError, match="too far in the future"):
            _verify(keys, proof, now_ms=NOW + 1_000)

    def test_clock_skew_tolerance(self, keys):
        # Proof minted 25s in the "past" relative to verifier: within skew.
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        assert (
            _verify(keys, proof, now_ms=proof.data.expires_at - 5_000)
            == keys["client_pub"]
        )

    def test_tampered_identity_key_fails(self, keys):
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        other = _random_key()
        tampered = AuthProof(
            data=AuthProofData(
                action=proof.data.action,
                identity_key=public_key_from_private(other).hex(),
                expires_at=proof.data.expires_at,
                nonce=proof.data.nonce,
            ),
            signature=proof.signature,
        )
        with pytest.raises(AuthProofError, match="invalid signature"):
            _verify(keys, tampered)

    def test_tampered_nonce_fails(self, keys):
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        tampered = AuthProof(
            data=AuthProofData(
                action=proof.data.action,
                identity_key=proof.data.identity_key,
                expires_at=proof.data.expires_at,
                nonce="EVILNONCE",
            ),
            signature=proof.signature,
        )
        with pytest.raises(AuthProofError, match="invalid signature"):
            _verify(keys, tampered)

    def test_wrong_verifier_key_fails(self, keys):
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        eavesdropper = _random_key()
        with pytest.raises(AuthProofError, match="invalid signature"):
            verify_auth_proof(
                eavesdropper,
                proof,
                "login",
                single_use_store=MemorySingleUseStore(),
                now_ms=NOW + 1_000,
            )


class TestSingleUse:
    def test_replay_rejected(self, keys):
        store = MemorySingleUseStore()
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        assert _verify(keys, proof, store=store) == keys["client_pub"]
        with pytest.raises(AuthProofError, match="already used"):
            _verify(keys, proof, store=store)

    def test_invalid_proof_does_not_populate_store(self, keys):
        store = MemorySingleUseStore()
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        bad = AuthProof(
            data=AuthProofData(
                action="delete",  # wrong action — fails before single-use
                identity_key=proof.data.identity_key,
                expires_at=proof.data.expires_at,
                nonce=proof.data.nonce,
            ),
            signature=proof.signature,
        )
        with pytest.raises(AuthProofError):
            _verify(keys, bad, store=store)
        assert len(store) == 0

    def test_evict_expired(self):
        # Fresh timestamps: the store prunes against wall-clock time.
        now = int(time.time() * 1000)
        store = MemorySingleUseStore()
        assert store.insert_if_not_exists("n1", expires_at=now + 100)
        assert store.insert_if_not_exists("n2", expires_at=now - 100)
        # n2 was already expired on insert; the first evict drops it, n1 stays.
        assert store.evict_expired(now_ms=now) == 1
        assert "n1" in store._seen
        assert "n2" not in store._seen
        # past n1's expiry it is evicted too
        assert store.evict_expired(now_ms=now + 200) == 1
        assert "n1" not in store._seen

    def test_sqlite_store(self):
        now = int(time.time() * 1000)
        store = SqliteSingleUseStore(":memory:")
        try:
            assert store.insert_if_not_exists("abc", expires_at=now + 1000)
            assert not store.insert_if_not_exists("abc", expires_at=now + 1000)
            assert store.insert_if_not_exists("def", expires_at=now - 1000)
            assert store.evict_expired(now_ms=now) == 1
        finally:
            store.close()

    def test_sqlite_store_in_verification(self, keys):
        store = SqliteSingleUseStore(":memory:")
        try:
            proof = create_auth_proof(
                keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
            )
            assert _verify(keys, proof, store=store) == keys["client_pub"]
            with pytest.raises(AuthProofError, match="already used"):
                _verify(keys, proof, store=store)
        finally:
            store.close()


class TestMalformedInput:
    def test_missing_fields(self):
        with pytest.raises(AuthProofError, match="missing field"):
            AuthProofData.from_dict({"action": "login"})

    def test_bad_action_chars(self, keys):
        with pytest.raises(AuthProofError, match="control characters"):
            create_auth_proof(keys["client_priv"], keys["server_pub"], "login\nadmin")
        with pytest.raises(AuthProofError, match="non-empty"):
            create_auth_proof(keys["client_priv"], keys["server_pub"], "")

    def test_bad_protocol(self, keys):
        with pytest.raises(AuthProofError, match="form \\[2, name\\]"):
            create_auth_proof(
                keys["client_priv"],
                keys["server_pub"],
                "login",
                protocol=(1, "x"),
            )

    def test_bad_identity_key(self, keys):
        with pytest.raises(AuthProofError, match="33-byte"):
            create_auth_proof(keys["client_priv"], "deadbeef", "login")

    def test_from_dict_malformed(self):
        with pytest.raises(AuthProofError, match="malformed proof"):
            AuthProof.from_dict({"data": {"action": "login"}})
        with pytest.raises(AuthProofError, match="signature"):
            AuthProof.from_dict(
                {
                    "data": {
                        "action": "login",
                        "identityKey": "02" + "ab" * 32,
                        "expiresAt": 1_000,
                        "nonce": "n",
                    },
                    "signature": "zz",
                }
            )

    def test_normalize_body_none(self):
        with pytest.raises(TypeError):
            normalize_body(None)


class TestCanonicalEncoding:
    def test_vector(self):
        data = AuthProofData(
            action="login",
            identity_key="02" + "ab" * 32,
            expires_at=1_750_000_000_123,
            nonce="bm9uY2U=",
        )
        assert data.canonical_bytes() == (
            b"login\n02" + b"ab" * 32 + b"\n1750000000123\nbm9uY2U="
        )
        bound = data.canonical_bytes(b"hi")
        assert bound == data.canonical_bytes() + b"\x02hi"
        # empty bound payload is distinct from none
        assert data.canonical_bytes(b"") == data.canonical_bytes() + b"\x00"

    def test_generate_nonce(self):
        n1 = generate_nonce()
        n2 = generate_nonce()
        assert n1 != n2
        import base64

        assert len(base64.b64decode(n1)) == 32


class TestCheckAuthProofData:
    def test_pure_checks(self, keys):
        data = AuthProofData(
            action="login",
            identity_key=keys["client_pub"],
            expires_at=NOW + 60_000,
            nonce="x",
        )
        check_auth_proof_data(data, "login", now_ms=NOW)  # ok
        with pytest.raises(AuthProofError, match="action mismatch"):
            check_auth_proof_data(data, "other", now_ms=NOW)
        with pytest.raises(AuthProofError, match="expired"):
            check_auth_proof_data(data, "login", now_ms=NOW + 60_000)


class TestAdapter:
    def test_starlette_adapter_optional(self):
        # The ASGI adapter lives behind the starlette extra; importing the
        # package core must not require it.
        import bsv_brc.brc138 as mod

        assert mod.create_auth_proof is not None

    def test_adapter_import(self):
        pytest.importorskip("starlette")
        from bsv_brc.brc138.adapters.asgi import (
            AuthProofMiddleware,
            PROOF_HEADER,
            get_proof_from_header_or_body,
        )

        assert PROOF_HEADER == "x-bsv-auth-proof"
        body = b'{"prompt":"x"}'
        headers = [(b"x-bsv-auth-proof", json.dumps({"data": {}}).encode())]
        assert get_proof_from_header_or_body(body, headers) == {"data": {}}
        headers2 = [(b"content-type", b"application/json")]
        assert get_proof_from_header_or_body(
            b'{"proof": {"a": 1}}', headers2
        ) == {"a": 1}
        assert get_proof_from_header_or_body(b"", headers2) is None

    def test_middleware_end_to_end(self, keys):
        starlette = pytest.importorskip("starlette")
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.testclient import TestClient

        from bsv_brc.brc138.adapters.asgi import AuthProofMiddleware

        app = Starlette()

        async def login(request):
            identity = request.scope["bsv_auth_proof"]["identity_key"]
            return JSONResponse({"ok": True, "identity": identity})

        app.add_route("/login", login, methods=["GET", "POST"])

        wrapped = AuthProofMiddleware(
            app,
            wallet=type(
                "W",
                (),
                {"get_private_key": lambda self, k: keys["server_priv"]},
            )(),
            expected_action="login",
            single_use_store=MemorySingleUseStore(),
        )
        client = TestClient(wrapped)
        proof = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )

        # no proof -> 401
        r = client.get("/login")
        assert r.status_code == 401

        # valid proof in header -> 200 with identity
        r = client.get(
            "/login",
            headers={"x-bsv-auth-proof": json.dumps(proof.to_dict())},
        )
        assert r.status_code == 200
        assert r.json()["identity"] == keys["client_pub"]

        # replay -> 401
        r = client.get(
            "/login",
            headers={"x-bsv-auth-proof": json.dumps(proof.to_dict())},
        )
        assert r.status_code == 401

        # proof in JSON body -> 200
        proof2 = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "login", now_ms=NOW
        )
        r = client.post("/login", json={"proof": proof2.to_dict()})
        assert r.status_code == 200

        # tampered action -> 401
        proof3 = create_auth_proof(
            keys["client_priv"], keys["server_pub"], "delete", now_ms=NOW
        )
        r = client.get(
            "/login",
            headers={"x-bsv-auth-proof": json.dumps(proof3.to_dict())},
        )
        assert r.status_code == 401


class TestTopLevelExports:
    def test_brc138_importable_from_root(self):
        import bsv_brc

        assert bsv_brc.create_auth_proof is create_auth_proof
        assert bsv_brc.verify_auth_proof is verify_auth_proof
        assert bsv_brc.DEFAULT_PROTOCOL == (2, "bsv auth proof")
