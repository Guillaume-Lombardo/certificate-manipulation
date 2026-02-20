from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
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
