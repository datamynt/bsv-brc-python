"""
BRC-138: Single-Use Signed Proofs for Request Authentication.

A lightweight, signature-based, expiry-bound, single-use request
authentication primitive — login and one-shot actions without a full
BRC-103 mutual-authentication session. Interoperates with the reference
``@bsv/auth`` implementation by default (same protocol, window and skew).

Core (no framework dependency):

    from bsv_brc.brc138 import (
        create_auth_proof, verify_auth_proof,
        AuthProof, MemorySingleUseStore,
    )

    proof = create_auth_proof(client_private_key, server_public_key, "login")
    # ... transmit proof.to_dict() ...

    identity = verify_auth_proof(
        server_private_key, proof, "login",
        single_use_store=MemorySingleUseStore(),
    )

Optional Starlette middleware (requires the ``starlette`` extra):

    from bsv_brc.brc138.adapters.asgi import AuthProofMiddleware
"""

from bsv_brc.brc138.proof import (
    DEFAULT_CLOCK_SKEW_MS,
    DEFAULT_PROTOCOL,
    DEFAULT_VALIDITY_WINDOW_MS,
    NONCE_BYTES,
    AuthProof,
    AuthProofData,
    AuthProofError,
    check_auth_proof_data,
    create_auth_proof,
    generate_nonce,
    normalize_body,
    verify_auth_proof,
)
from bsv_brc.brc138.store import (
    MemorySingleUseStore,
    SingleUseStore,
    SqliteSingleUseStore,
)

__all__ = [
    "AuthProof",
    "AuthProofData",
    "AuthProofError",
    "DEFAULT_CLOCK_SKEW_MS",
    "DEFAULT_PROTOCOL",
    "DEFAULT_VALIDITY_WINDOW_MS",
    "NONCE_BYTES",
    "MemorySingleUseStore",
    "SingleUseStore",
    "SqliteSingleUseStore",
    "check_auth_proof_data",
    "create_auth_proof",
    "generate_nonce",
    "normalize_body",
    "verify_auth_proof",
]
