"""
BRC-94: Verifiable Revelation of Shared Secrets Using Schnorr Protocol.

Allows a prover to demonstrate knowledge of an ECDH shared secret
without revealing any private keys. The verifier can independently
confirm the shared secret is authentic using only public keys.

References:
    BRC-94: https://bsv.brc.dev/key-derivation/0094
    BRC-69: https://bsv.brc.dev/key-derivation/0069
    BRC-72: https://bsv.brc.dev/key-derivation/0072
    BRC-93: https://bsv.brc.dev/key-derivation/0093 (limitations addressed)
"""

from bsv_brc.brc094.schnorr import generate_proof, verify_proof
from bsv_brc.brc094.linkage import (
    verify_counterparty_linkage,
    create_counterparty_linkage_revelation,
)

__all__ = [
    "generate_proof",
    "verify_proof",
    "verify_counterparty_linkage",
    "create_counterparty_linkage_revelation",
]
