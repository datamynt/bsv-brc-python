"""
bsv-brc — higher-level BRC protocol building blocks for Python.

The protocol-layer companion to ``bsv-sdk`` (py-sdk): where bsv-sdk gives
you keys, transactions, SPV and the client side of overlay/auth, bsv-brc
adds the pieces that make *building a BRC app* easy — identity
certificates, HTTP mutual auth + micropayment middleware, and the
server-side overlay machinery py-sdk leaves open.

Modules:
    brc052       — BRC-52 identity certificates (AES-256-GCM, issuance)
    brc094       — BRC-94 verifiable ECDH shared secrets (Schnorr proof)
    brc104       — BRC-103/104 mutual auth, ASGI adapter over bsv.auth
    brc105       — BRC-105 HTTP 402 micropayments (middleware + client)
    brc138       — BRC-138 single-use signed proofs (request authentication)
    brc22        — BRC-22 server-side overlay topic submission (/submit)
    brc24        — BRC-24 server-side lookup services / feed (/lookup)
    brc87        — BRC-87 tm_/ls_ overlay name validation
    overlay      — OverlayEngine: a runnable overlay node (submit + lookup)
    integration  — build_brc_app: auth + payments pre-stacked (Starlette)
    crypto       — shared BRC-42/43 key derivation primitives

The auth/payment/overlay glue lives behind the optional ``starlette``
extra: ``pip install "bsv-brc[starlette]"``.

Compatible with @bsv/sdk (TypeScript). License: Open BSV.
"""

__version__ = "0.5.0"

# Always-available core (no optional dependencies).
from bsv_brc.brc105.types import (
    BSVPayment,
    PaymentResult,
    PricingStrategy,
    StaticPricing,
)
from bsv_brc.brc105.nonce import NonceManager
from bsv_brc.brc22 import (
    AdmittanceInstructions,
    TaggedBEEF,
    TopicEngine,
    TopicManager,
    UnknownTopicError,
)
from bsv_brc.brc24 import LookupService, OutputRef, ResolvedOutput
from bsv_brc.brc87 import (
    InvalidNameError,
    is_valid_service_name,
    is_valid_topic_name,
    validate_service_name,
    validate_topic_name,
)
from bsv_brc.overlay import (
    DEFAULT_OVERLAY_HOST,
    InMemoryOverlayStorage,
    OverlayClient,
    OverlayEngine,
    OverlayStorage,
    SqliteOverlayStorage,
    UnknownServiceError,
)
from bsv_brc.brc138 import (
    DEFAULT_CLOCK_SKEW_MS,
    DEFAULT_PROTOCOL,
    DEFAULT_VALIDITY_WINDOW_MS,
    NONCE_BYTES,
    AuthProof,
    AuthProofData,
    AuthProofError,
    MemorySingleUseStore,
    SingleUseStore,
    SqliteSingleUseStore,
    check_auth_proof_data,
    create_auth_proof,
    generate_nonce,
    normalize_body,
    verify_auth_proof,
)

__all__ = [
    "__version__",
    # BRC-105 core
    "BSVPayment",
    "PaymentResult",
    "PricingStrategy",
    "StaticPricing",
    "NonceManager",
    # BRC-138 single-use signed proofs
    "AuthProof",
    "AuthProofData",
    "AuthProofError",
    "SingleUseStore",
    "MemorySingleUseStore",
    "SqliteSingleUseStore",
    "DEFAULT_PROTOCOL",
    "DEFAULT_VALIDITY_WINDOW_MS",
    "DEFAULT_CLOCK_SKEW_MS",
    "NONCE_BYTES",
    "check_auth_proof_data",
    "create_auth_proof",
    "generate_nonce",
    "normalize_body",
    "verify_auth_proof",
    # BRC-22 overlay (server side)
    "TopicManager",
    "TopicEngine",
    "UnknownTopicError",
    "AdmittanceInstructions",
    "TaggedBEEF",
    # BRC-24 lookup + overlay node
    "LookupService",
    "OutputRef",
    "ResolvedOutput",
    "OverlayEngine",
    "OverlayStorage",
    "InMemoryOverlayStorage",
    "SqliteOverlayStorage",
    "UnknownServiceError",
    "OverlayClient",
    "DEFAULT_OVERLAY_HOST",
    # BRC-87 overlay name validation
    "validate_topic_name",
    "validate_service_name",
    "is_valid_topic_name",
    "is_valid_service_name",
    "InvalidNameError",
    # Integration helpers (require the `starlette` extra)
    "build_brc_app",
    "make_internalize_verifier",
    "build_internalize_args",
    "PathPricing",
    "get_identity",
    "get_payment",
]


def __getattr__(name: str):
    """Lazily expose the Starlette-dependent integration helpers.

    Keeps ``import bsv_brc`` working without the ``starlette`` extra; the
    integration names raise a clear ImportError only when actually used.
    """
    _integration_names = {
        "build_brc_app",
        "make_internalize_verifier",
        "build_internalize_args",
        "PathPricing",
        "get_identity",
        "get_payment",
    }
    if name in _integration_names:
        from bsv_brc import integration

        return getattr(integration, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
