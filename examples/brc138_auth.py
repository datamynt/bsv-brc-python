"""
BRC-138 single-use signed proof — a login endpoint in one request.

Demo of the module: proves you hold an identity key (no BRC-103 handshake,
no session) in a single request. Shows both sides with one wallet pair —
in production the client signs in a browser wallet and the server verifies
with its own identity key.
"""

from bsv import PrivateKey

from bsv_brc.brc138 import (
    AuthProofError,
    MemorySingleUseStore,
    create_auth_proof,
    verify_auth_proof,
)
from bsv_brc.crypto.keys import public_key_from_private

# --- Setup: a client wallet and a server wallet (random keys for the demo) ---
client_key = PrivateKey()
server_key = PrivateKey()
server_pub = public_key_from_private(server_key.serialize()).hex()

# The server's single-use store: consumed nonces are rejected atomically.
# Swap in SqliteSingleUseStore (or any DB with a unique index) for a
# multi-instance deployment.
store = MemorySingleUseStore()

# --- Client: sign a "login" proof toward the server's identity key ---
proof = create_auth_proof(
    client_key.serialize(),
    server_pub,
    "login",  # the only action this proof authorizes
)
print("proof:", proof.data.action, "for identity", proof.data.identity_key[:16], "…")

# --- Wire form: a plain JSON object (signature as byte values, per BRC-138) ---
wire = proof.to_dict()
print("wire size:", len(str(wire)), "bytes (expires in 2 min, single use)")

# --- Server: verify (shape → action → freshness → signature → single-use) ---
try:
    identity = verify_auth_proof(
        server_key.serialize(),
        wire,
        "login",
        single_use_store=store,
    )
    print("authenticated:", identity == proof.data.identity_key)
except AuthProofError as exc:
    print("rejected:", exc)

# --- A replay of the same proof is rejected ---
try:
    verify_auth_proof(server_key.serialize(), wire, "login", single_use_store=store)
    print("replay ACCEPTED (bug!)")
except AuthProofError as exc:
    print("replay rejected:", exc)