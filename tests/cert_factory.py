from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509.oid import NameOID


def make_self_signed_pem(common_name: str, *, valid_days: int = 365) -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(tz=UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    certificate = (
        x509
        .CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.PEM).decode("utf-8")


def make_self_signed_der(common_name: str, *, valid_days: int = 365) -> bytes:
    """Build a self-signed certificate encoded as DER.

    Args:
        common_name (str): Subject common name.
        valid_days (int): Validity duration in days.

    Returns:
        bytes: DER-encoded certificate bytes.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(tz=UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    certificate = (
        x509
        .CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.DER)


def make_pkcs7_bundle_pem(common_names: list[str]) -> str:
    """Build a PKCS7 PEM bundle with multiple self-signed certificates.

    Args:
        common_names (list[str]): Subject common names to include.

    Returns:
        str: PEM-encoded PKCS7 bundle.
    """
    certs: list[x509.Certificate] = []
    for common_name in common_names:
        private_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(tz=UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certs.append(
            x509
            .CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(private_key=private_key, algorithm=hashes.SHA256()),
        )

    return pkcs7.serialize_certificates(certs, Encoding.PEM).decode("utf-8")


def make_pkcs7_bundle_der(common_names: list[str]) -> bytes:
    """Build a PKCS7 DER bundle with multiple self-signed certificates.

    Args:
        common_names (list[str]): Subject common names to include.

    Returns:
        bytes: DER-encoded PKCS7 bundle.
    """
    certs: list[x509.Certificate] = []
    for common_name in common_names:
        private_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(tz=UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certs.append(
            x509
            .CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(private_key=private_key, algorithm=hashes.SHA256()),
        )

    return pkcs7.serialize_certificates(certs, Encoding.DER)
