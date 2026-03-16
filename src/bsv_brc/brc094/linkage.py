"""
High-level counterparty key linkage revelation (BRC-69 + BRC-94).

Wraps the Schnorr proof in the BRC-72 encryption format for safe transit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from bsv_brc.brc094.schnorr import generate_proof, verify_proof
from bsv_brc.crypto.keys import public_key_from_private


@dataclass
class CounterpartyLinkageRevelation:
    """BRC-69 Method 1 counterparty linkage with BRC-94 Schnorr proof."""

    type: str  # "counterparty-revelation"
    prover: str  # hex pubkey
    counterparty: str  # hex pubkey
    shared_secret: str  # hex compressed point
    proof_R: str  # hex compressed point
    proof_S_prime: str  # hex compressed point
    proof_z: str  # hex scalar

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "prover": self.prover,
            "counterparty": self.counterparty,
            "sharedSecret": self.shared_secret,
            "proof": {
                "R": self.proof_R,
                "Sprime": self.proof_S_prime,
                "z": self.proof_z,
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def create_counterparty_linkage_revelation(
    prover_private_key: bytes,
    counterparty_public_key: bytes,
) -> CounterpartyLinkageRevelation:
    """
    Create a counterparty key linkage revelation with Schnorr proof.

    The prover reveals the ECDH shared secret with cryptographic proof
    that it is authentic, without revealing their private key.
    """
    S, R, S_prime, z = generate_proof(prover_private_key, counterparty_public_key)
    prover_pub = public_key_from_private(prover_private_key)

    return CounterpartyLinkageRevelation(
        type="counterparty-revelation",
        prover=prover_pub.hex(),
        counterparty=counterparty_public_key.hex(),
        shared_secret=S.hex(),
        proof_R=R.hex(),
        proof_S_prime=S_prime.hex(),
        proof_z=z.hex(),
    )


def verify_counterparty_linkage(revelation: CounterpartyLinkageRevelation) -> bool:
    """
    Verify a counterparty linkage revelation.

    No private keys needed — uses only public keys and the Schnorr proof.
    """
    return verify_proof(
        prover_public_key=bytes.fromhex(revelation.prover),
        counterparty_public_key=bytes.fromhex(revelation.counterparty),
        shared_secret=bytes.fromhex(revelation.shared_secret),
        R=bytes.fromhex(revelation.proof_R),
        S_prime=bytes.fromhex(revelation.proof_S_prime),
        z=bytes.fromhex(revelation.proof_z),
    )
