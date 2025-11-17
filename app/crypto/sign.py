"""
RSA signature helpers for signing and verifying SHA-256 hashes.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

def rsa_sign_hash(rsa_priv: rsa.RsaPrivateKey, data_hash: bytes) -> bytes:
    """
    Sign a SHA-256 hash using RSA PKCS#1 v1.5.
    
    Args:
        rsa_priv: RSA private key object.
        data_hash: 32-byte SHA-256 digest to sign.
    
    Returns:
        Signature bytes.
    """
    if len(data_hash) != 32:
        raise ValueError("Hash must be exactly 32 bytes for SHA-256.")

    signature_bytes = rsa_priv.sign(
        data_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature_bytes


def rsa_verify_signature(pub_or_cert, data_hash: bytes, signature_bytes: bytes) -> bool:
    """
    Verify an RSA signature against a SHA-256 hash.
    
    Args:
        pub_or_cert: RSA public key or x509 certificate containing the public key.
        data_hash: 32-byte SHA-256 digest that was signed.
        signature_bytes: Signature to verify.
    
    Returns:
        True if signature is valid, False otherwise.
    """
    # get public key from certificate if necessary
    if isinstance(pub_or_cert, x509.Certificate):
        pub_key = pub_or_cert.public_key()
    else:
        pub_key = pub_or_cert

    try:
        pub_key.verify(
            signature_bytes,
            data_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
