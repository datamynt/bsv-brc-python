"""
BRC-52 identity certificate construction, signing, and issuance.

Certificates bind field values (email, name, etc.) to a subject's public key,
signed by a certifier using BRC-43 derived keys.

The binary format matches Certificate.toBinary() in the BSV SDK.
"""

import base64
import hashlib
import struct

from bsv import PrivateKey, PublicKey
from bsv.curve import curve, curve_multiply, curve_add

from bsv_brc.crypto import keys


def make_certificate_type(unique_string: str) -> str:
    """
    Create a BRC-52 certificate type ID from a unique string.

    Convention: SHA-256 hash of a unique URI, base64-encoded.
    Example: ``make_certificate_type("example.com/email/v1")``
    """
    return base64.b64encode(
        hashlib.sha256(unique_string.encode("utf-8")).digest()
    ).decode()


def _varint(n: int) -> bytes:
    """Bitcoin-style variable-length integer encoding."""
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def build_binary(
    cert_type: str,
    serial_number: str,
    subject: str,
    certifier: str,
    revocation_outpoint: str,
    fields: dict[str, str],
) -> bytes:
    """
    Build the canonical BRC-52 certificate binary.

    Matches Certificate.toBinary() in the BSV SDK exactly.

    Format:
        type(32) + serial(32) + subject(33) + certifier(33)
        + revocation_txid(32) + output_index(varint)
        + num_fields(varint) + fields sorted alphabetically:
            name_len(varint) + name(utf8) + value_len(varint) + value(utf8)
    """
    txid_hex, output_idx = revocation_outpoint.split(".")
    field_names = sorted(fields.keys())

    field_data = b""
    for name in field_names:
        value = fields[name]
        name_b = name.encode("utf-8")
        value_b = value.encode("utf-8")
        field_data += _varint(len(name_b)) + name_b + _varint(len(value_b)) + value_b

    return (
        base64.b64decode(cert_type)
        + base64.b64decode(serial_number)
        + bytes.fromhex(subject)
        + bytes.fromhex(certifier)
        + bytes.fromhex(txid_hex)
        + _varint(int(output_idx))
        + _varint(len(field_names))
        + field_data
    )


def sign(
    certifier_private_key: bytes,
    cert_type: str,
    serial_number: str,
    cert_binary: bytes,
) -> str:
    """
    Sign a BRC-52 certificate using BRC-43 derived key.

    Uses "certificate signature" protocol with counterparty = "anyone".
    Returns DER-encoded ECDSA signature as hex string.
    """
    key_id = f"{cert_type} {serial_number}"
    derived_priv, _ = keys.derive_signing_key(
        certifier_private_key, 2, "certificate signature", key_id
    )

    cert_hash = hashlib.sha256(cert_binary).digest()
    sk = PrivateKey(derived_priv)
    # Sign the pre-computed hash — use identity hasher so SDK doesn't double-hash
    sig = sk.sign(cert_hash, hasher=lambda x: x)
    return sig.hex()


def verify_signature(
    certifier_public_key: bytes,
    cert_type: str,
    serial_number: str,
    cert_binary: bytes,
    signature_hex: str,
) -> bool:
    """
    Verify a BRC-52 certificate signature.

    Derives the expected signing public key from the certifier's public key
    and verifies the ECDSA-DER signature over SHA-256(cert_binary).
    """
    key_id = f"{cert_type} {serial_number}"
    inv = keys.invoice_number(2, "certificate signature", key_id)
    h = keys._hmac_sha256(certifier_public_key, inv)

    h_int = int.from_bytes(h, "big")
    pub = PublicKey(certifier_public_key)
    h_point = curve_multiply(h_int, curve.g)
    derived_pub_point = curve_add(pub.point(), h_point)
    derived_pub = PublicKey(derived_pub_point)

    cert_hash = hashlib.sha256(cert_binary).digest()

    try:
        return derived_pub.verify(
            bytes.fromhex(signature_hex), cert_hash, hasher=lambda x: x
        )
    except Exception:
        return False


def issue(
    certifier_private_key: bytes,
    cert_type: str,
    subject_key: str,
    field_values: dict[str, str],
    serial_number: str,
    encrypted_field_keys: dict[str, str],
    revocation_outpoint: str = "0" * 64 + ".0",
) -> dict:
    """
    Issue a BRC-52 certificate.

    Main entry point for certifier servers. Handles:
      1. Decrypt revelation keys from client (keyID = "{serial} {field}")
      2. Encrypt field values with revelation keys
      3. Re-encrypt revelation keys for subject (keyID = "{field}" only)
      4. Build binary, sign, return certificate dict

    The keyringForSubject uses keyID = "{field}" only, for compatibility
    with wallet-toolbox's decryptFields().
    """
    from bsv_brc.brc052 import aes

    subject_pub = bytes.fromhex(subject_key)
    certifier_pub = keys.public_key_from_private(certifier_private_key).hex()

    encrypted_fields: dict[str, str] = {}
    keyring_for_subject: dict[str, str] = {}

    for field_name, enc_key_b64 in encrypted_field_keys.items():
        if field_name not in field_values:
            raise ValueError(f"No value provided for field '{field_name}'")

        # Decrypt revelation key (client used keyID = "{serial} {field}")
        sym_key_incoming = keys.derive_symmetric_key(
            certifier_private_key,
            subject_pub,
            2,
            "certificate field encryption",
            f"{serial_number} {field_name}",
        )
        revelation_key = aes.decrypt(
            sym_key_incoming, base64.b64decode(enc_key_b64)
        )

        # Encrypt field value with revelation key
        encrypted_fields[field_name] = base64.b64encode(
            aes.encrypt(revelation_key, field_values[field_name].encode("utf-8"))
        ).decode()

        # Re-encrypt revelation key for subject (keyID = field name only)
        sym_key_subject = keys.derive_symmetric_key(
            certifier_private_key,
            subject_pub,
            2,
            "certificate field encryption",
            field_name,
        )
        keyring_for_subject[field_name] = base64.b64encode(
            aes.encrypt(sym_key_subject, revelation_key)
        ).decode()

    cert_binary = build_binary(
        cert_type,
        serial_number,
        subject_key,
        certifier_pub,
        revocation_outpoint,
        encrypted_fields,
    )
    sig_hex = sign(certifier_private_key, cert_type, serial_number, cert_binary)

    return {
        "type": cert_type,
        "serialNumber": serial_number,
        "subject": subject_key,
        "certifier": certifier_pub,
        "revocationOutpoint": revocation_outpoint,
        "fields": encrypted_fields,
        "signature": sig_hex,
        "keyringForSubject": keyring_for_subject,
        "keyringRevealer": certifier_pub,
    }
