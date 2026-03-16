"""
AES-256-GCM encryption compatible with the BSV SDK.

The BSV SDK uses a non-standard 32-byte IV (nonce) for AES-GCM.
Wire format: IV(32 bytes) + ciphertext + authTag(16 bytes)
"""

import os

from Cryptodome.Cipher import AES


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-GCM encrypt with BSV SDK wire format.

    Returns: IV(32) + ciphertext + authTag(16)
    """
    iv = os.urandom(32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    return iv + ciphertext + auth_tag


def decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-256-GCM decrypt from BSV SDK wire format.

    Args:
        key: 32-byte symmetric key.
        data: IV(32) + ciphertext + authTag(16)

    Raises:
        ValueError: If authentication tag verification fails or data too short.
    """
    if len(data) < 48:
        raise ValueError(f"Ciphertext too short: {len(data)} bytes, minimum 48")
    iv = data[:32]
    auth_tag = data[-16:]
    ciphertext = data[32:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, auth_tag)
