"""Tests for BRC-52 certificate construction, signing, and issuance."""

import base64
import os

import coincurve
import pytest
from bsv_brc.brc052 import certificate, encrypt, decrypt
from bsv_brc.crypto import keys


def make_keypair():
    priv = os.urandom(32)
    pub = coincurve.PrivateKey(priv).public_key.format(compressed=True)
    return priv, pub


class TestMakeCertificateType:
    def test_deterministic(self):
        a = certificate.make_certificate_type("example.com/email/v1")
        b = certificate.make_certificate_type("example.com/email/v1")
        assert a == b

    def test_different_inputs(self):
        a = certificate.make_certificate_type("type-a")
        b = certificate.make_certificate_type("type-b")
        assert a != b

    def test_base64_format(self):
        t = certificate.make_certificate_type("test")
        raw = base64.b64decode(t)
        assert len(raw) == 32


class TestBuildBinary:
    def test_deterministic(self):
        args = dict(
            cert_type=certificate.make_certificate_type("test/v1"),
            serial_number=base64.b64encode(b"\x00" * 32).decode(),
            subject="02" + "ab" * 32,
            certifier="03" + "cd" * 32,
            revocation_outpoint="00" * 32 + ".0",
            fields={"email": "encrypted_value", "name": "encrypted_name"},
        )
        assert certificate.build_binary(**args) == certificate.build_binary(**args)

    def test_fields_sorted_alphabetically(self):
        binary = certificate.build_binary(
            cert_type=certificate.make_certificate_type("test"),
            serial_number=base64.b64encode(b"\x00" * 32).decode(),
            subject="02" + "ab" * 32,
            certifier="03" + "cd" * 32,
            revocation_outpoint="00" * 32 + ".0",
            fields={"zebra": "z", "alpha": "a"},
        )
        assert binary.find(b"alpha") < binary.find(b"zebra")

    def test_minimum_length(self):
        binary = certificate.build_binary(
            cert_type=certificate.make_certificate_type("t"),
            serial_number=base64.b64encode(b"\x00" * 32).decode(),
            subject="02" + "00" * 32,
            certifier="03" + "00" * 32,
            revocation_outpoint="00" * 32 + ".0",
            fields={},
        )
        assert len(binary) >= 164


class TestSignAndVerify:
    def test_sign_then_verify(self):
        cert_priv, cert_pub = make_keypair()
        cert_type = certificate.make_certificate_type("test/v1")
        serial = base64.b64encode(os.urandom(32)).decode()

        binary = certificate.build_binary(
            cert_type=cert_type,
            serial_number=serial,
            subject="02" + "ab" * 32,
            certifier=cert_pub.hex(),
            revocation_outpoint="00" * 32 + ".0",
            fields={"email": "encrypted_data"},
        )

        sig = certificate.sign(cert_priv, cert_type, serial, binary)
        assert certificate.verify_signature(cert_pub, cert_type, serial, binary, sig)

    def test_wrong_key_fails(self):
        cert_priv, cert_pub = make_keypair()
        _, wrong_pub = make_keypair()

        cert_type = certificate.make_certificate_type("test")
        serial = base64.b64encode(os.urandom(32)).decode()

        binary = certificate.build_binary(
            cert_type=cert_type,
            serial_number=serial,
            subject="02" + "ab" * 32,
            certifier=cert_pub.hex(),
            revocation_outpoint="00" * 32 + ".0",
            fields={},
        )

        sig = certificate.sign(cert_priv, cert_type, serial, binary)
        assert not certificate.verify_signature(wrong_pub, cert_type, serial, binary, sig)

    def test_tampered_binary_fails(self):
        cert_priv, cert_pub = make_keypair()
        cert_type = certificate.make_certificate_type("test")
        serial = base64.b64encode(os.urandom(32)).decode()

        binary = certificate.build_binary(
            cert_type=cert_type,
            serial_number=serial,
            subject="02" + "ab" * 32,
            certifier=cert_pub.hex(),
            revocation_outpoint="00" * 32 + ".0",
            fields={"f": "v"},
        )

        sig = certificate.sign(cert_priv, cert_type, serial, binary)
        tampered = binary[:-1] + bytes([binary[-1] ^ 0xFF])
        assert not certificate.verify_signature(cert_pub, cert_type, serial, tampered, sig)


class TestIssue:
    def test_full_flow(self):
        """Client encrypts -> certifier issues -> client decrypts field."""
        cert_priv, cert_pub = make_keypair()
        subj_priv, subj_pub = make_keypair()

        cert_type = certificate.make_certificate_type("example.com/identity/v1")
        serial = base64.b64encode(os.urandom(32)).decode()
        email = "alice@example.com"

        revelation_key = os.urandom(32)
        sym_key = keys.derive_symmetric_key(
            subj_priv, cert_pub,
            2, "certificate field encryption",
            f"{serial} email",
        )
        enc_rev_key = base64.b64encode(encrypt(sym_key, revelation_key)).decode()

        cert = certificate.issue(
            certifier_private_key=cert_priv,
            cert_type=cert_type,
            subject_key=subj_pub.hex(),
            field_values={"email": email},
            serial_number=serial,
            encrypted_field_keys={"email": enc_rev_key},
        )

        assert cert["type"] == cert_type
        assert cert["serialNumber"] == serial
        assert cert["subject"] == subj_pub.hex()
        assert cert["certifier"] == cert_pub.hex()
        assert "email" in cert["fields"]
        assert "email" in cert["keyringForSubject"]

        decrypted = decrypt(revelation_key, base64.b64decode(cert["fields"]["email"]))
        assert decrypted.decode("utf-8") == email

    def test_wallet_keyring_recovery(self):
        """Wallet recovers revelation key using fieldName-only keyID."""
        cert_priv, cert_pub = make_keypair()
        subj_priv, subj_pub = make_keypair()

        cert_type = certificate.make_certificate_type("test/v1")
        serial = base64.b64encode(os.urandom(32)).decode()

        revelation_key = os.urandom(32)
        sym_key = keys.derive_symmetric_key(
            subj_priv, cert_pub,
            2, "certificate field encryption",
            f"{serial} email",
        )

        cert = certificate.issue(
            certifier_private_key=cert_priv,
            cert_type=cert_type,
            subject_key=subj_pub.hex(),
            field_values={"email": "bob@example.com"},
            serial_number=serial,
            encrypted_field_keys={"email": base64.b64encode(encrypt(sym_key, revelation_key)).decode()},
        )

        wallet_sym_key = keys.derive_symmetric_key(
            subj_priv, cert_pub,
            2, "certificate field encryption",
            "email",
        )
        recovered = decrypt(wallet_sym_key, base64.b64decode(cert["keyringForSubject"]["email"]))
        assert recovered == revelation_key

        decrypted = decrypt(recovered, base64.b64decode(cert["fields"]["email"]))
        assert decrypted.decode("utf-8") == "bob@example.com"

    def test_signature_verifiable(self):
        """Issued certificate has a valid signature."""
        cert_priv, cert_pub = make_keypair()
        subj_priv, subj_pub = make_keypair()

        cert_type = certificate.make_certificate_type("test/v1")
        serial = base64.b64encode(os.urandom(32)).decode()

        revelation_key = os.urandom(32)
        sym_key = keys.derive_symmetric_key(
            subj_priv, cert_pub,
            2, "certificate field encryption",
            f"{serial} data",
        )

        cert = certificate.issue(
            certifier_private_key=cert_priv,
            cert_type=cert_type,
            subject_key=subj_pub.hex(),
            field_values={"data": "value"},
            serial_number=serial,
            encrypted_field_keys={"data": base64.b64encode(encrypt(sym_key, revelation_key)).decode()},
        )

        binary = certificate.build_binary(
            cert["type"], cert["serialNumber"], cert["subject"],
            cert["certifier"], cert["revocationOutpoint"], cert["fields"],
        )
        assert certificate.verify_signature(cert_pub, cert["type"], cert["serialNumber"], binary, cert["signature"])

    def test_missing_field_value_raises(self):
        cert_priv, _ = make_keypair()
        _, subj_pub = make_keypair()

        with pytest.raises(ValueError, match="No value provided"):
            certificate.issue(
                certifier_private_key=cert_priv,
                cert_type=certificate.make_certificate_type("t"),
                subject_key=subj_pub.hex(),
                field_values={},
                serial_number=base64.b64encode(b"\x00" * 32).decode(),
                encrypted_field_keys={"email": base64.b64encode(b"\x00" * 80).decode()},
            )

    def test_multiple_fields(self):
        """Issue certificate with multiple fields."""
        cert_priv, cert_pub = make_keypair()
        subj_priv, subj_pub = make_keypair()

        cert_type = certificate.make_certificate_type("multi/v1")
        serial = base64.b64encode(os.urandom(32)).decode()

        fields = {"email": "alice@example.com", "name": "Alice", "org": "Acme"}
        enc_keys = {}
        rev_keys = {}

        for field_name in fields:
            rev_key = os.urandom(32)
            rev_keys[field_name] = rev_key
            sym = keys.derive_symmetric_key(
                subj_priv, cert_pub,
                2, "certificate field encryption",
                f"{serial} {field_name}",
            )
            enc_keys[field_name] = base64.b64encode(encrypt(sym, rev_key)).decode()

        cert = certificate.issue(
            certifier_private_key=cert_priv,
            cert_type=cert_type,
            subject_key=subj_pub.hex(),
            field_values=fields,
            serial_number=serial,
            encrypted_field_keys=enc_keys,
        )

        for field_name, expected_value in fields.items():
            decrypted = decrypt(rev_keys[field_name], base64.b64decode(cert["fields"][field_name]))
            assert decrypted.decode("utf-8") == expected_value
