"""
General utility functions for encoding, hashing, timestamps, and certificates.
"""

import os
import base64
import hashlib
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def current_time_ms() -> int:
    """Return the current UTC time in milliseconds since Unix epoch."""
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)

def encode_b64(data_bytes: bytes) -> str:
    """Convert bytes into a Base64-encoded UTF-8 string."""
    return base64.b64encode(data_bytes).decode('utf-8')

def decode_b64(b64_string: str) -> bytes:
    """Convert a Base64-encoded UTF-8 string back into bytes."""
    try:
        return base64.b64decode(b64_string)
    except (TypeError, base64.binascii.Error):
        raise ValueError("Invalid Base64 input.")

def sha256_hexdigest(data_bytes: bytes) -> str:
    """Return the SHA-256 hash of data as a 64-character hex string."""
    return hashlib.sha256(data_bytes).hexdigest()

def sha256_digest(data_bytes: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 hash of the input bytes."""
    return hashlib.sha256(data_bytes).digest()

def random_nonce(size: int = 16) -> bytes:
    """Generate a secure random nonce of specified byte length."""
    return os.urandom(size)

def certificate_to_b64(cert_obj: x509.Certificate) -> str:
    """Serialize an x509.Certificate object to a Base64 string."""
    pem_bytes = cert_obj.public_bytes(serialization.Encoding.PEM)
    return encode_b64(pem_bytes)

def b64_to_certificate(b64_cert: str) -> x509.Certificate:
    """Deserialize a Base64 string back into an x509.Certificate object."""
    try:
        pem_bytes = decode_b64(b64_cert)
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as e:
        raise ValueError(f"Could not decode certificate: {e}")
