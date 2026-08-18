"""BRC-138 cross-implementation interop driver (Python side).

Proves byte-compatibility with the reference TypeScript implementation
@bsv/auth: creates proofs Python -> Node, and verifies proofs Node -> Python.
Run from the repo root after installing the interop deps (see
examples/brc138_interop/README.md).
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
from pathlib import Path

from bsv import PrivateKey

from bsv_brc.brc138 import (
    AuthProof,
    create_auth_proof,
    verify_auth_proof,
)
from bsv_brc.crypto.keys import public_key_from_private

INTEROP_DIR = str(Path(__file__).resolve().parent)
NOW = int(time.time() * 1000)


def rand_hex() -> str:
    return PrivateKey().serialize().hex()


def call_node(mode: str, *args) -> dict:
    result = subprocess.run(
        ["node", f"{INTEROP_DIR}/interop.mjs", mode, *args],
        capture_output=True,
        text=True,
        check=True,
        cwd=INTEROP_DIR,  # resolve @bsv/auth + @bsv/sdk from node_modules here
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def main() -> None:
    client_priv = rand_hex()
    server_priv = rand_hex()
    server_pub = public_key_from_private(bytes.fromhex(server_priv)).hex()
    client_pub = public_key_from_private(bytes.fromhex(client_priv)).hex()

    # ---- 1. Python creates, Node verifies (bodyless login) ----
    proof = create_auth_proof(
        bytes.fromhex(client_priv), server_pub, "login", now_ms=NOW
    )
    vector = {
        "clientPrivHex": client_priv,
        "serverPrivHex": server_priv,
        "action": "login",
        "proof": proof.to_dict(),
    }
    with open("/tmp/interop_vector.json", "w") as fh:
        json.dump(vector, fh)
    res = call_node("verifyPy", "/tmp/interop_vector.json")
    assert res.get("valid") is True, f"Node rejected Python proof: {res}"
    assert res.get("identityKey") == client_pub, res
    print("[1/4] Python proof verified by @bsv/auth (Node): OK")

    # ---- 2. Python creates with bound payload, Node verifies ----
    payload = b'{"username":"alice","role":"admin"}'
    proof2 = create_auth_proof(
        bytes.fromhex(client_priv),
        server_pub,
        "updateProfile",
        payload=payload,
        now_ms=NOW,
    )
    vector2 = {
        "clientPrivHex": client_priv,
        "serverPrivHex": server_priv,
        "action": "updateProfile",
        "proof": proof2.to_dict(),
        "payloadB64": b64(payload),
    }
    with open("/tmp/interop_vector2.json", "w") as fh:
        json.dump(vector2, fh)
    res2 = call_node("verifyPy", "/tmp/interop_vector2.json")
    assert res2.get("valid") is True, f"Node rejected Python bound proof: {res2}"
    print("[2/4] Python bound-payload proof verified by @bsv/auth (Node): OK")

    # ---- 3. Node creates, Python verifies (bodyless) ----
    res3 = call_node("create", client_priv, server_priv, "login")
    py_proof = AuthProof.from_dict({"data": res3["data"], "signature": res3["signature"]})
    assert py_proof.data.identity_key == client_pub, res3
    identity = verify_auth_proof(
        bytes.fromhex(server_priv),
        py_proof,
        "login",
        now_ms=NOW + 1_000,
    )
    assert identity == client_pub
    print("[3/4] Node proof verified by bsv_brc.brc138 (Python): OK")

    # ---- 4. Node creates with bound payload, Python verifies ----
    payload4 = b"\x00\x01\xff raw binary body"
    res4 = call_node("create", client_priv, server_priv, "transcribe", b64(payload4))
    py_proof4 = AuthProof.from_dict({"data": res4["data"], "signature": res4["signature"]})
    identity4 = verify_auth_proof(
        bytes.fromhex(server_priv),
        py_proof4,
        "transcribe",
        payload=payload4,
        now_ms=NOW + 1_000,
    )
    assert identity4 == client_pub
    print("[4/4] Node bound-payload proof verified by bsv_brc.brc138 (Python): OK")

    print("ALL INTEROP CHECKS PASSED")


if __name__ == "__main__":
    sys.exit(main())
