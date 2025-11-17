"""
Utility functions for performing a Diffie–Hellman key exchange.

This module:
- Builds DH parameters (p, g)
- Generates a DH key pair
- Computes the shared secret value
- Produces a 16-byte AES key derived from that secret
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import dh

# Predefined MODP group (RFC 3526 - 2048-bit, Group 14)
# Converted from hex to integer for p
_prime_hex = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14370F8911152DCB0563"
    "5B8D293E94D2AD5E5168FF5BBD80862238D3B3675A9E6A4C"
    "0F1C9F82C2E0C66475C30344A3A36B6908FF3B55163D9AB2"
    "0E2CA890DCB88BF203D2A95E1907D3A3A93A275AD48B4E36"
    "4047562D5302B6957CB8D643941125AE0A939E8C530983A8"
    "8932338CCF3BAD6273970E1FE378A52F8A819C64B76466B34"
    "0F0B6C9387F97A3EF1416B9B071F609E162383A006918663"
    "539A57348F140C9323F14E0118F128D3D718C9B0E8AEE3D0"
    "C04E4E6A2C91A5EB8B12423E88846E2004A411F568D883B3"
    "B9577D9E471F1A7E8C6872953110E104813C1C634D2B6693"
    "401666B442A0693E4B8ADE55342C0C1558332D586834A81E"
    "4F038F3E38244B9C0E63471BD4709A763A90235C9A637202"
    "773C6F34E07D27F8A4D3220F03A2E8A1FFFFFFFFFFFFFFFF"
)

_prime_val = int(_prime_hex, 16)
_gen_val = 2

_param_numbers = dh.DHParameterNumbers(_prime_val, _gen_val)
_param_obj = _param_numbers.parameters()


def make_keypair() -> tuple[dh.DHPrivateKey, int]:
    """
    Creates a Diffie–Hellman key pair.

    Returns:
        (private_key, public_value)
    """
    priv_key = _param_obj.generate_private_key()
    pub_key = priv_key.public_key().public_numbers().y
    return priv_key, pub_key


def get_shared_secret(my_private: dh.DHPrivateKey, peer_public: int) -> bytes:
    """
    Uses the local private key and the peer's public value
    to compute the raw shared secret.
    """
    peer_nums = dh.DHPublicNumbers(peer_public, _param_numbers)
    peer_key = peer_nums.public_key()
    secret_bytes = my_private.exchange(peer_key)
    return secret_bytes


def make_aes_key(secret_material: bytes) -> bytes:
    """
    Produces a 16-byte AES key by hashing the DH shared secret
    with SHA-256 and taking the first 16 bytes.
    """
    hashed = hashlib.sha256(secret_material).digest()
    return hashed[:16]
