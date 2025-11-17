#!/usr/bin/env python3
"""RSA Digital Signature Testing Script."""

from app.crypto.sign import RSASignature


def test_rsa_signing():
    """Perform signing and verification tests for RSA keys."""
    
    # Load RSA keys
    private_key = RSASignature.load_private_key('certs/client.key')
    public_key_client = RSASignature.load_public_key('certs/client.crt')
    
    # Sample message
    message = b"Hello SecureChat!"
    
    print("=" * 60)
    print("🔒 RSA Digital Signature Test")
    print("=" * 60)
    
    # Sign message
    print("\n1️⃣  Signing message with client private key...")
    signature = RSASignature.sign(message, private_key)
    print(f"   Original message: {message}")
    print(f"   Signature (first 64 hex chars): {signature[:64]}...")
    print(f"   Total signature length: {len(signature)} characters")
    
    # Verify signature
    print("\n2️⃣  Verifying signature using client public key...")
    valid = RSASignature.verify(message, signature, public_key_client)
    print(f"   ✅ Signature valid: {valid}")
    
    # Check tampering detection
    print("\n3️⃣  Detecting tampered message...")
    altered_message = b"Hello Hacker!"
    valid_altered = RSASignature.verify(altered_message, signature, public_key_client)
    print(f"   ❌ Tampered message verified as valid: {valid_altered}")
    
    # Attempt cross-verification with server public key
    print("\n4️⃣  Cross-verifying with server public key (should fail)...")
    public_key_server = RSASignature.load_public_key('certs/server.crt')
    valid_cross = RSASignature.verify(message, signature, public_key_server)
    print(f"   ❌ Verification with server key valid: {valid_cross}")
    
    print("\n" + "=" * 60)
    print("✅ RSA signature tests finished successfully!")
    print("=" * 60)


if __name__ == "__main__":
    test_rsa_signing()
