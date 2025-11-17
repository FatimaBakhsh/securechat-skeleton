#!/usr/bin/env python3
"""X.509 Certificate Validation Test Script."""

from pathlib import Path
from app.crypto.pki import CertificateValidator, validate_certificate, validate_peer_certificate


def load_certificates():
    """Load CA, server, and client certificates."""
    
    print("=" * 70)
    print("🔐 Certificate Loading")
    print("=" * 70)
    
    certs_path = Path('certs')
    
    # Load CA certificate
    print("\n1️⃣ Loading CA certificate...")
    try:
        ca_cert = CertificateValidator.load_certificate(certs_path / 'ca.crt')
        print("   ✅ CA certificate loaded successfully")
    except Exception as e:
        print(f"   ❌ Failed to load CA certificate: {e}")
        return
    
    # Load Server certificate
    print("\n2️⃣ Loading server certificate...")
    try:
        server_cert = CertificateValidator.load_certificate(certs_path / 'server.crt')
        print("   ✅ Server certificate loaded successfully")
    except Exception as e:
        print(f"   ❌ Failed to load server certificate: {e}")
        return
    
    # Load Client certificate
    print("\n3️⃣ Loading client certificate...")
    try:
        client_cert = CertificateValidator.load_certificate(certs_path / 'client.crt')
        print("   ✅ Client certificate loaded successfully")
    except Exception as e:
        print(f"   ❌ Failed to load client certificate: {e}")
        return
    
    print("\n" + "=" * 70)
    return ca_cert, server_cert, client_cert


def check_certificate_validity(certs):
    """Verify current validity period of each certificate."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Validity Check")
    print("=" * 70)
    
    # CA validity
    print("\n1️⃣ Checking CA certificate validity...")
    valid, msg = CertificateValidator.is_valid_now(ca_cert)
    print(f"   Valid: {valid} | Message: {msg}")
    
    # Server validity
    print("\n2️⃣ Checking server certificate validity...")
    valid, msg = CertificateValidator.is_valid_now(server_cert)
    print(f"   Valid: {valid} | Message: {msg}")
    
    # Client validity
    print("\n3️⃣ Checking client certificate validity...")
    valid, msg = CertificateValidator.is_valid_now(client_cert)
    print(f"   Valid: {valid} | Message: {msg}")
    
    print("\n" + "=" * 70)


def verify_ca_self_signed(certs):
    """Confirm that the CA certificate is self-signed."""
    
    ca_cert, _, _ = certs
    
    print("\n" + "=" * 70)
    print("🔐 CA Self-Signed Verification")
    print("=" * 70)
    
    print("\n1️⃣ Verifying if CA is self-signed...")
    valid, msg = CertificateValidator.verify_self_signed(ca_cert)
    if valid:
        print("   ✅ CA is correctly self-signed")
    else:
        print(f"   ❌ Self-sign verification failed: {msg}")
    
    print("\n" + "=" * 70)


def verify_certificate_signatures(certs):
    """Check signatures of server and client certificates against the CA."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Signature Verification")
    print("=" * 70)
    
    # Server cert
    print("\n1️⃣ Verifying server certificate signature...")
    valid, msg = CertificateValidator.verify_signature(server_cert, ca_cert)
    print(f"   {'✅ Valid' if valid else '❌ Invalid'} | {msg}")
    
    # Client cert
    print("\n2️⃣ Verifying client certificate signature...")
    valid, msg = CertificateValidator.verify_signature(client_cert, ca_cert)
    print(f"   {'✅ Valid' if valid else '❌ Invalid'} | {msg}")
    
    print("\n" + "=" * 70)


def validate_certificate_chain(certs):
    """Validate the full certificate chain from end-entity to CA."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Chain Validation")
    print("=" * 70)
    
    # Server chain
    print("\n1️⃣ Server certificate chain check...")
    valid, msg = CertificateValidator.verify_chain(server_cert, ca_cert)
    print(f"   {'✅ Valid' if valid else '❌ Invalid'} | {msg}")
    
    # Client chain
    print("\n2️⃣ Client certificate chain check...")
    valid, msg = CertificateValidator.verify_chain(client_cert, ca_cert)
    print(f"   {'✅ Valid' if valid else '❌ Invalid'} | {msg}")
    
    print("\n" + "=" * 70)


def extract_certificate_info(certs):
    """Display details from each certificate."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Information")
    print("=" * 70)
    
    for name, cert in [('CA', ca_cert), ('Server', server_cert), ('Client', client_cert)]:
        info = CertificateValidator.get_certificate_info(cert)
        print(f"\n{name} Certificate:")
        print(f"   Subject: {info['subject']}")
        print(f"   Issuer: {info['issuer']}")
        print(f"   Serial: {info['serial']}")
        print(f"   Valid From: {info['valid_from']}")
        print(f"   Valid To: {info['valid_to']}")
        print(f"   Key Size: {info['key_size']} bits")
        print(f"   Signature Algorithm: {info.get('signature_algorithm', 'N/A')}")
        print(f"   SANs: {info['subject_alt_names']}")
    
    print("\n" + "=" * 70)


def test_convenience_validators():
    """Use higher-level helper functions for certificate validation."""
    
    print("\n" + "=" * 70)
    print("🔐 Convenience Validator Tests")
    print("=" * 70)
    
    certs_dir = Path('certs')
    
    # Server
    print("\n1️⃣ Server certificate validation...")
    valid, info = validate_certificate(certs_dir / 'server.crt', certs_dir / 'ca.crt')
    print(f"   Valid: {valid} | Subject: {info['subject']} | Issuer: {info['issuer']}")
    
    # Client
    print("\n2️⃣ Client certificate validation...")
    valid, info = validate_certificate(certs_dir / 'client.crt', certs_dir / 'ca.crt')
    print(f"   Valid: {valid} | Subject: {info['subject']} | Issuer: {info['issuer']}")
    
    # Expected CN check
    print("\n3️⃣ Server CN validation with expected name...")
    valid, msg = validate_peer_certificate(certs_dir / 'server.crt', certs_dir / 'ca.crt', expected_cn='server')
    print(f"   Valid: {valid} | Message: {msg}")
    
    print("\n4️⃣ Server CN validation with wrong name...")
    valid, msg = validate_peer_certificate(certs_dir / 'server.crt', certs_dir / 'ca.crt', expected_cn='wrong_name')
    print(f"   Valid: {valid} | Message: {msg}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🔐 X.509 Certificate Validation Test Suite")
    print("=" * 70 + "\n")
    
    certs = load_certificates()
    if certs:
        check_certificate_validity(certs)
        verify_ca_self_signed(certs)
        verify_certificate_signatures(certs)
        validate_certificate_chain(certs)
        extract_certificate_info(certs)
    
    test_convenience_validators()
    
    print("\n" + "=" * 70)
    print("✅ All certificate validation tests finished successfully")
    print("=" * 70)
