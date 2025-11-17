#!/usr/bin/env python3
"""Diffie-Hellman key exchange testing module."""

from app.crypto.dh import DiffieHellman, perform_dh_exchange, exchange_public_keys, complete_exchange


def run_dh_full_test():
    """Simulate a complete DH key exchange between two participants."""
    
    print("=" * 70)
    print("🔐 Diffie-Hellman Full Exchange Test")
    print("=" * 70)
    
    # Generate private/public keys for Alice
    print("\n1️⃣ Generating Alice's key pair...")
    alice_priv = DiffieHellman.generate_private_key()
    alice_pub = DiffieHellman.get_public_key(alice_priv)
    print("   ✅ Alice's key pair ready")
    
    # Generate private/public keys for Bob
    print("\n2️⃣ Generating Bob's key pair...")
    bob_priv = DiffieHellman.generate_private_key()
    bob_pub = DiffieHellman.get_public_key(bob_priv)
    print("   ✅ Bob's key pair ready")
    
    # Serialize keys for “network transmission”
    print("\n3️⃣ Serializing public keys for exchange...")
    alice_pub_bytes = DiffieHellman.serialize_public_key(alice_pub)
    bob_pub_bytes = DiffieHellman.serialize_public_key(bob_pub)
    print(f"   Alice's public key: {len(alice_pub_bytes)} bytes")
    print(f"   Bob's public key: {len(bob_pub_bytes)} bytes")
    
    # Simulate exchange
    print("\n4️⃣ Exchanging public keys...")
    alice_received = DiffieHellman.deserialize_public_key(bob_pub_bytes)
    bob_received = DiffieHellman.deserialize_public_key(alice_pub_bytes)
    print("   ✅ Public keys exchanged successfully")
    
    # Compute shared secrets
    print("\n5️⃣ Computing shared secrets...")
    alice_secret = DiffieHellman.compute_shared_secret(alice_priv, alice_received)
    bob_secret = DiffieHellman.compute_shared_secret(bob_priv, bob_received)
    print(f"   Alice's secret (hex): {alice_secret.hex()[:64]}...")
    print(f"   Bob's secret (hex): {bob_secret.hex()[:64]}...")
    
    # Verify shared secrets
    print("\n6️⃣ Validating shared secrets...")
    if alice_secret == bob_secret:
        print("   ✅ Secrets match — exchange successful")
    else:
        print("   ❌ Secrets mismatch! Check DH implementation")
        return
    
    # Derive session keys (AES-128)
    print("\n7️⃣ Deriving session keys (16 bytes)...")
    alice_key = DiffieHellman.derive_key(alice_secret, key_length=16)
    bob_key = DiffieHellman.derive_key(bob_secret, key_length=16)
    print(f"   Alice's session key: {alice_key.hex()}")
    print(f"   Bob's session key: {bob_key.hex()}")
    
    # Validate session keys
    print("\n8️⃣ Verifying session keys...")
    if alice_key == bob_key:
        print("   ✅ Session keys match — ready for encryption")
    else:
        print("   ❌ Session keys mismatch!")
    
    # Display DH parameters
    print("\n" + "=" * 70)
    p, g = DiffieHellman.get_parameters()
    print("📊 DH Parameters:")
    print(f"   Generator g: {g}")
    print(f"   Prime p (truncated): {str(p)[:64]}... ({p.bit_length()} bits)")
    print("=" * 70)
    print("✅ Full DH exchange test complete")
    print("=" * 70)


def run_dh_wrapper_test():
    """Test convenient wrapper functions for key exchange."""
    
    print("\n\n" + "=" * 70)
    print("🔐 Diffie-Hellman Wrapper Functions Test")
    print("=" * 70)
    
    # Alice generates keys and sends public key
    print("\n1️⃣ Alice prepares key pair...")
    alice_priv = DiffieHellman.generate_private_key()
    alice_pub, alice_bytes = exchange_public_keys(alice_priv)
    print(f"   Alice's public key size: {len(alice_bytes)} bytes")
    
    # Bob generates keys and sends public key
    print("\n2️⃣ Bob prepares key pair...")
    bob_priv = DiffieHellman.generate_private_key()
    bob_pub, bob_bytes = exchange_public_keys(bob_priv)
    print(f"   Bob's public key size: {len(bob_bytes)} bytes")
    
    # Alice completes exchange
    print("\n3️⃣ Alice computes shared secret & session key...")
    alice_res = complete_exchange(alice_priv, bob_bytes)
    print(f"   Shared secret (hex): {alice_res['shared_secret'].hex()[:64]}...")
    print(f"   Session key: {alice_res['session_key'].hex()}")
    
    # Bob completes exchange
    print("\n4️⃣ Bob computes shared secret & session key...")
    bob_res = complete_exchange(bob_priv, alice_bytes)
    print(f"   Shared secret (hex): {bob_res['shared_secret'].hex()[:64]}...")
    print(f"   Session key: {bob_res['session_key'].hex()}")
    
    # Verify agreement
    print("\n5️⃣ Confirming session keys match...")
    if alice_res['session_key'] == bob_res['session_key']:
        print("   ✅ Session keys match — DH exchange verified")
    else:
        print("   ❌ Session keys mismatch!")
    
    print("\n" + "=" * 70)
    print("✅ Wrapper functions test complete")
    print("=" * 70)


if __name__ == "__main__":
    run_dh_full_test()
    run_dh_wrapper_test()
