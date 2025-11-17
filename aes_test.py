#!/usr/bin/env python3
"""Comprehensive AES-128 Encryption/Decryption Test Suite."""

import os
from app.crypto.aes import AES128, encrypt_message, decrypt_message


def basic_aes_test():
    """Verify basic AES-128 encryption and decryption functionality."""
    
    print("="*70)
    print("🔒 AES-128: Basic Encryption/Decryption Test")
    print("="*70)

    key = os.urandom(16)
    print(f"\n1️⃣ Generated AES Key: {key.hex()}")

    message = "Hello SecureChat!"
    print(f"2️⃣ Original Message: {message}")

    print("\n3️⃣ Encrypting message...")
    ciphertext = AES128.encrypt(message, key)
    print(f"   Ciphertext (hex): {ciphertext}")
    print(f"   Length: {len(ciphertext)//2} bytes")

    print("\n4️⃣ Decrypting message...")
    decrypted = AES128.decrypt_str(ciphertext, key)
    print(f"   Decrypted: {decrypted}")

    print("\n5️⃣ Verification...")
    if decrypted == message:
        print("   ✅ Success! Encryption and decryption match.")
    else:
        print(f"   ❌ Failure! Got {decrypted} instead of {message}")

    print("="*70, "\n")


def varied_messages_test():
    """Test AES with multiple message types including Unicode, empty, and long messages."""

    print("="*70)
    print("🔒 AES-128: Various Message Types Test")
    print("="*70)

    key = os.urandom(16)
    messages = [
        "Short",
        "This is a longer test message requiring padding.",
        "Special chars: !@#$%^&*()",
        "Numbers: 1234567890",
        "Unicode: こんにちは世界 🔐",
        "",
        "x"*100
    ]

    for idx, msg in enumerate(messages, 1):
        print(f"\n{idx}️⃣ Test case: '{msg[:30]}{'...' if len(msg) > 30 else ''}' ({len(msg)} chars)")
        try:
            encrypted = AES128.encrypt(msg, key)
            decrypted = AES128.decrypt_str(encrypted, key)
            print("   ✅ Success" if decrypted == msg else "   ❌ Mismatch")
        except Exception as e:
            print(f"   ❌ Error: {e}")

    print("="*70, "\n")


def tampering_detection_test():
    """Ensure AES detects tampering via invalid padding."""
    
    print("="*70)
    print("🔒 AES-128: Tampering Detection Test")
    print("="*70)

    key = os.urandom(16)
    message = "Sensitive Data"
    print(f"\n1️⃣ Original Message: {message}")

    encrypted = AES128.encrypt(message, key)
    print(f"2️⃣ Ciphertext: {encrypted}")

    tampered = encrypted[:-2] + "FF"
    print("\n3️⃣ Tampering with ciphertext...")
    print(f"   Tampered: {tampered}")

    print("\n4️⃣ Attempting decryption...")
    try:
        AES128.decrypt_str(tampered, key)
        print("   ❌ Decryption succeeded unexpectedly!")
    except ValueError as e:
        print("   ✅ Decryption failed as expected (tampering detected).")
        print(f"   Error: {e}")

    print("="*70, "\n")


def wrong_key_test():
    """Verify decryption fails with incorrect AES key."""

    print("="*70)
    print("🔒 AES-128: Wrong Key Test")
    print("="*70)

    key_correct = os.urandom(16)
    key_wrong = os.urandom(16)
    message = "Sensitive Data"

    print(f"\n1️⃣ Correct Key: {key_correct.hex()}")
    print(f"2️⃣ Wrong Key:   {key_wrong.hex()}")
    print(f"3️⃣ Message: {message}")

    encrypted = AES128.encrypt(message, key_correct)
    print(f"\n4️⃣ Encrypted: {encrypted[:64]}...")

    print("\n5️⃣ Decrypting with wrong key...")
    try:
        decrypted = AES128.decrypt_str(encrypted, key_wrong)
        if decrypted != message:
            print("   ✅ Wrong key did not produce correct plaintext.")
        else:
            print("   ❌ Wrong key incorrectly decrypted message!")
    except Exception as e:
        print(f"   ✅ Decryption failed as expected. Error: {type(e).__name__}: {e}")

    print("="*70, "\n")


def pkcs7_padding_test():
    """Test PKCS#7 padding and unpadding functionality."""

    print("="*70)
    print("🔒 AES-128: PKCS#7 Padding Test")
    print("="*70)

    cases = [
        (b"", 16),
        (b"a", 16),
        (b"ab", 16),
        (b"a"*16, 16),
        (b"a"*32, 16),
    ]

    for plaintext, block in cases:
        print(f"\n1️⃣ Plaintext length: {len(plaintext)} bytes")
        padded = AES128.pad(plaintext, block)
        print(f"2️⃣ Padded length: {len(padded)} bytes, Padding byte: {padded[-1]}")
        unpadded = AES128.unpad(padded, block)
        print("3️⃣ ✅ Padding/unpadding correct" if unpadded == plaintext else "3️⃣ ❌ Mismatch")

    print("="*70, "\n")


def convenience_functions_test():
    """Test encrypt_message and decrypt_message helper functions."""

    print("="*70)
    print("🔒 AES-128: Convenience Functions Test")
    print("="*70)

    key = os.urandom(16)
    message = "Testing helper functions!"

    print(f"\n1️⃣ Message: {message}")

    ciphertext = encrypt_message(message, key)
    print(f"\n2️⃣ Encrypted (helper): {ciphertext[:64]}...")

    decrypted_str = decrypt_message(ciphertext, key, as_string=True)
    decrypted_bytes = decrypt_message(ciphertext, key, as_string=False)

    print(f"\n3️⃣ Decrypted (str): {decrypted_str}")
    print(f"4️⃣ Decrypted (bytes): {decrypted_bytes}")

    if decrypted_str == message and decrypted_bytes == message.encode('utf-8'):
        print("5️⃣ ✅ Convenience functions work correctly!")

    print("="*70, "\n")


if __name__ == "__main__":
    basic_aes_test()
    varied_messages_test()
    tampering_detection_test()
    wrong_key_test()
    pkcs7_padding_test()
    convenience_functions_test()
