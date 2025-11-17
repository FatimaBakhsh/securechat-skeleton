"""
AES-128 ECB mode encryption and decryption utilities with PKCS#7 padding.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16  # AES block size in bytes for AES-128

def aes_encrypt(aes_key: bytes, data: bytes) -> bytes:
    """
    Encrypt data using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        aes_key: 16-byte AES key.
        data: plaintext bytes.
    
    Returns:
        Encrypted ciphertext bytes.
    """
    if len(aes_key) != 16:
        raise ValueError("AES key must be exactly 16 bytes for AES-128.")

    # pad the plaintext
    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
    padded_data = padder.update(data) + padder.finalize()

    # create AES ECB cipher and encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted


def aes_decrypt(aes_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 ECB and remove PKCS#7 padding.
    
    Args:
        aes_key: 16-byte AES key.
        ciphertext: encrypted bytes.
    
    Returns:
        Decrypted plaintext bytes.
    """
    if len(aes_key) != 16:
        raise ValueError("AES key must be exactly 16 bytes for AES-128.")

    try:
        # create AES ECB cipher and decrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        # remove padding
        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        plaintext = unpadder.update(padded_plain) + unpadder.finalize()

        return plaintext
    except ValueError:
        raise ValueError("Decryption failed: key may be wrong or data is corrupted.")
