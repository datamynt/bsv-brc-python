"""Capture pinned cross-implementation vectors for the regression test.

Uses FIXED keys and times so the resulting JSON can be embedded in
tests/test_brc138_interop.py. Each vector is certified against the reference
@bsv/auth implementation (Node) at capture time.
"""
from __future__ import annotations

import base64
import json
import subprocess

from bsv_brc.brc138 import create_auth_proof
from bsv_brc.crypto.keys import public_key_from_private

# Fixed identities (generated once, used only as test fixtures).
CLIENT_PRIV = "524c969962c3128365f5c147cea31c8cad0bad2b745020c0ad42f4d7a1785b2e"
SERVER_PRIV = "9777da3f30df19f2c1cd61420e9688e673205dd02bb4738291eaceac5eecdcf9"
FIXED_NOW = int(__import__("time").time() * 1000)  # fresh epoch ms at capture


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def certify_proof(proof_dict: dict, action: str, payload_b64=None) -> dict:
    """Ask the reference @bsv/auth (Node) to verify; assert it accepts."""
    vector = {
        "clientPrivHex": CLIENT_PRIV,
        "serverPrivHex": SERVER_PRIV,
        "action": action,
        "proof": proof_dict,
    }
    if payload_b64 is not None:
        vector["payloadB64"] = payload_b64
    with open("/tmp/cap_vector.json", "w") as fh:
        json.dump(vector, fh)
    res = subprocess.run(
        ["node", "interop.mjs", "verifyPy", "/tmp/cap_vector.json"],
        capture_output=True,
        text=True,
        check=True,
    )
    out = json.loads(res.stdout.strip().splitlines()[-1])
    assert out.get("valid") is True, f"Node rejected vector: {out}"
    return out


def main() -> None:
    server_pub = public_key_from_private(bytes.fromhex(SERVER_PRIV)).hex()

    # Vector 1: Python-created, bodyless login — certified by Node.
    proof1 = create_auth_proof(
        bytes.fromhex(CLIENT_PRIV), server_pub, "login", now_ms=FIXED_NOW
    )
    certify_proof(proof1.to_dict(), "login")
    print("### PYTHON LOGIN (certified by Node)")
    print(json.dumps(proof1.to_dict()))

    # Vector 2: Python-created, bound payload — certified by Node.
    payload2 = b'{"username":"alice","role":"admin"}'
    proof2 = create_auth_proof(
        bytes.fromhex(CLIENT_PRIV),
        server_pub,
        "updateProfile",
        payload=payload2,
        now_ms=FIXED_NOW,
    )
    certify_proof(proof2.to_dict(), "updateProfile", b64(payload2))
    print("### PYTHON UPDATE PROFILE (certified by Node)")
    print(json.dumps(proof2.to_dict()))
    print(f"### PAYLOAD2: {b64(payload2)}")

    # Vectors 3/4: Node-created — Python must verify them.
    for tag, action, payload in (
        ("login", "login", None),
        ("transcribe", "transcribe", b"\x00\x01\xff raw binary body"),
    ):
        args = ["node", "interop.mjs", "create", CLIENT_PRIV, SERVER_PRIV, action]
        if payload is not None:
            args.append(b64(payload))
        res = subprocess.run(args, capture_output=True, text=True, check=True)
        out = json.loads(res.stdout.strip().splitlines()[-1])
        print(f"### NODE {tag.upper()}")
        print(json.dumps(out["data"]))
        print(f"### NODE {tag.upper()} SIG: " + json.dumps(out["signature"]))
        if payload is not None:
            print(f"### NODE {tag.upper()} PAYLOAD: {b64(payload)}")


if __name__ == "__main__":
    main()