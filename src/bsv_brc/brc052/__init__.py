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

# Re-export the BRC-42/43 key primitives certificate issuance is built on,
# so a BRC-52 issuer (e.g. peck-certifier) has a single import surface and
# need not reach into bsv_brc.crypto separately. public_key_from_private in
# particular unblocks deriving the certifier's public key from its key.
from bsv_brc.crypto import (
    public_key_from_private,
    shared_secret,
    derive_symmetric_key,
    derive_signing_key,
    invoice_number,
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
    # BRC-42/43 key primitives (re-exported from bsv_brc.crypto)
    "public_key_from_private",
    "shared_secret",
    "derive_symmetric_key",
    "derive_signing_key",
    "invoice_number",
]
