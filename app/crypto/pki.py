"""
Certificate handling helpers for loading and validating X.509 identities.
Provides:
- fetch_root_ca(): Load CA certificate
- load_entity_credentials(): Load certificate + private key
- validate_cert(): Perform CA signature, date, and CN checks
- extract_cn(): Read the Common Name from a cert
"""

import pathlib
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


# certificate directory and CA path
CERT_FOLDER = pathlib.Path(__file__).resolve().parent.parent.parent / "certs"
CA_PATH = CERT_FOLDER / "ca_cert.pem"


def fetch_root_ca() -> x509.Certificate:
    """Load the root CA certificate from disk."""
    try:
        with open(CA_PATH, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print(f"CA certificate missing: {CA_PATH}")
        print("Run 'scripts/gen_ca.py' to generate a new CA.")
        raise
    except Exception as err:
        print(f"Failed to read CA certificate: {err}")
        raise


def load_entity_credentials(prefix: str) -> tuple[x509.Certificate, rsa.RsaPrivateKey]:
    """Load a certificate and its associated private key using a base prefix."""
    base = pathlib.Path(prefix)

    cert_path = base.with_name(base.name + "_cert.pem")
    key_path = base.with_name(base.name + "_private_key.pem")

    try:
        with open(cert_path, "rb") as f:
            cert_obj = x509.load_pem_x509_certificate(f.read())

        with open(key_path, "rb") as f:
            priv_key = load_pem_private_key(f.read(), password=None)

        return cert_obj, priv_key

    except FileNotFoundError as missing:
        print(f"Missing identity file: {missing.filename}")
        print("Use 'scripts/gen_cert.py' to generate identities.")
        raise
    except Exception as err:
        print(f"Unable to load credentials for '{prefix}': {err}")
        raise


def validate_cert(
    presented: x509.Certificate,
    ca_cert: x509.Certificate,
    required_cn: str
) -> bool:
    """Validate a certificate using CA signature, time validity, and CN match."""

    # verify CA signature
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            presented.signature,
            presented.tbs_certificate_bytes,
            padding.PKCS1v15(),
            presented.signature_hash_algorithm
        )
    except InvalidSignature:
        raise ValueError("BAD_CERT: CA signature verification failed.")
    except Exception as err:
        raise ValueError(f"BAD_CERT: Signature check error: {err}")

    # check certificate validity period
    now = datetime.datetime.now(datetime.timezone.utc)

    if now < presented.not_valid_before_utc:
        raise ValueError(f"BAD_CERT: Certificate not active until {presented.not_valid_before_utc}.")

    if now > presented.not_valid_after_utc:
        raise ValueError(f"BAD_CERT: Certificate expired on {presented.not_valid_after_utc}.")

    # check common name
    try:
        cn = presented.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        raise ValueError("BAD_CERT: Certificate has no Common Name.")

    if cn != required_cn:
        raise ValueError(f"BAD_CERT: Expected CN '{required_cn}', got '{cn}'.")

    return True


def extract_cn(cert: x509.Certificate) -> str:
    """Get the Common Name field from a certificate."""
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return "UNKNOWN"
