"""
BRC-52: Identity Certificates for BSV.

BRC-42: Key derivation via ECDH on secp256k1
BRC-43: HMAC-based symmetric key derivation with invoice numbers
BRC-52: Identity certificate binary format, signing, and issuance

Compatible with the BSV SDK (TypeScript) and wallet-toolbox.

References:
    BRC-52: https://bsv.brc.dev/peer-to-peer/0052
    BRC-53: https://bsv.brc.dev/wallet/0053
"""

from bsv_brc.brc052.aes import encrypt, decrypt
from bsv_brc.brc052.certificate import (
    build_binary,
    sign,
    verify_signature,
    issue,
    make_certificate_type,
)

__all__ = [
    # AES-256-GCM (BSV SDK layout)
    "encrypt",
    "decrypt",
    # BRC-52 certificates
    "build_binary",
    "sign",
    "verify_signature",
    "issue",
    "make_certificate_type",
]
