from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID


@dataclass
class CAKeys:
    private_key: ec.EllipticCurvePrivateKey
    certificate_pem: str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("utf-8"))


def create_ca() -> CAKeys:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMedia"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureMedia CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return CAKeys(private_key=private_key, certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"))


def issue_user_certificate(
    ca_private_key: ec.EllipticCurvePrivateKey,
    user_id: str,
    username: str,
    signing_public_key_pem: str,
) -> str:
    public_key = serialization.load_pem_public_key(signing_public_key_pem.encode("utf-8"))
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Signing public key must be EC")

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMedia"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, user_id),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMedia"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "SecureMedia CA"),
                ]
            )
        )
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def generate_group_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def _derive_wrap_key(shared_secret: bytes, context: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(shared_secret)


def wrap_group_key(
    group_key: bytes,
    user_agreement_public_key_pem: str,
    context: bytes,
) -> str:
    user_public_key = serialization.load_pem_public_key(
        user_agreement_public_key_pem.encode("utf-8")
    )
    if not isinstance(user_public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Agreement public key must be EC")

    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_private.exchange(ec.ECDH(), user_public_key)
    wrap_key = _derive_wrap_key(shared_secret, context)

    nonce = os.urandom(12)
    aesgcm = AESGCM(wrap_key)
    ciphertext = aesgcm.encrypt(nonce, group_key, context)

    eph_pub_pem = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    payload = {
        "ephemeral_pub_key_pem": eph_pub_pem.decode("utf-8"),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
    return _b64(json.dumps(payload).encode("utf-8"))


def unwrap_group_key(
    wrapped: str,
    user_agreement_private_key: ec.EllipticCurvePrivateKey,
    context: bytes,
) -> bytes:
    payload = json.loads(_b64d(wrapped))
    eph_pub = serialization.load_pem_public_key(
        payload["ephemeral_pub_key_pem"].encode("utf-8")
    )
    shared_secret = user_agreement_private_key.exchange(ec.ECDH(), eph_pub)
    wrap_key = _derive_wrap_key(shared_secret, context)

    nonce = _b64d(payload["nonce"])
    ciphertext = _b64d(payload["ciphertext"])
    return AESGCM(wrap_key).decrypt(nonce, ciphertext, context)
