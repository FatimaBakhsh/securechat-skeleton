"""
Utility script for producing a Root Certificate Authority (CA).

Outputs:
- RSA private key (ca_private_key.pem)
- Self-signed root certificate (ca_cert.pem)

This certificate acts as the trust anchor for the application.
"""

import argparse
import datetime
import pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_CERT_PATH = pathlib.Path(__file__).resolve().parent.parent / "certs"
ROOT_KEY_PATH = BASE_CERT_PATH / "ca_private_key.pem"
ROOT_CERT_PATH = BASE_CERT_PATH / "ca_cert.pem"


def create_root_authority(cn_value: str, days_valid: int = 365 * 10):
    """
    Generates a fresh RSA keypair and constructs a self-signed X.509 root certificate.

    Args:
        cn_value (str): Common Name of the root certificate.
        days_valid (int): Certificate validity period in days.
    """

    print(f"Creating Root CA Certificate for CN='{cn_value}'")

    # --- Generate RSA Key ---
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # --- Certificate Subject/Issuer Fields ---
    # Root CAs sign themselves, so subject == issuer.
    name_fields = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn_value),
    ])

    # --- Build Certificate ---
    current_time = datetime.datetime.now(datetime.timezone.utc)

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(name_fields)
        .issuer_name(name_fields)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current_time)
        .not_valid_after(current_time + datetime.timedelta(days=days_valid))
    )

    # --- Add Extensions ---
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )

    subject_key_id = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
    cert_builder = cert_builder.add_extension(subject_key_id, critical=False)

    authority_key_id = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())
    cert_builder = cert_builder.add_extension(authority_key_id, critical=False)

    # --- Sign Certificate ---
    root_certificate = cert_builder.sign(
        private_key=root_key,
        algorithm=hashes.SHA256()
    )

    # Ensure output directory exists
    BASE_CERT_PATH.mkdir(parents=True, exist_ok=True)

    # --- Write Private Key File ---
    with open(ROOT_KEY_PATH, "wb") as key_file:
        key_file.write(
            root_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )
    print(f"✔ Private key stored at: {ROOT_KEY_PATH}")

    # --- Write Certificate File ---
    with open(ROOT_CERT_PATH, "wb") as cert_file:
        cert_file.write(
            root_certificate.public_bytes(serialization.Encoding.PEM)
        )
    print(f"✔ Certificate stored at: {ROOT_CERT_PATH}")


def cli():
    """
    Command-line handler for executing CA generation.
    """

    parser = argparse.ArgumentParser(
        description="Generate a self-signed Root CA certificate and its private key."
    )
    parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="Common Name (CN) for the Root CA."
    )

    params = parser.parse_args()
    create_root_authority(cn_value=params.name)


if __name__ == "__main__":
    cli()
