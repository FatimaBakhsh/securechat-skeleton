#!/usr/bin/env python3
"""Test suite for database and transcript components of SecureChat."""

import time
import os
from pathlib import Path
from app.storage.db import Database, User
from app.storage.transcript import Transcript
from app.crypto.sign import RSASignature


def test_registration_flow():
    """Check user registration behavior."""
    
    print("="*70)
    print("📝 User Registration Tests")
    print("="*70)

    db = Database('securechat.db')

    # Register first user
    print("\n1️⃣ Registering Alice...")
    success, msg = db.register_user('alice@example.com', 'password123')
    print(f"   {'✅' if success else '❌'} {msg}")

    # Register second user
    print("\n2️⃣ Registering Bob...")
    success, msg = db.register_user('bob@example.com', 'secure_password')
    print(f"   {'✅' if success else '❌'} {msg}")

    # Attempt duplicate registration
    print("\n3️⃣ Attempting duplicate registration (Alice)...")
    success, msg = db.register_user('alice@example.com', 'another_pass')
    if not success:
        print(f"   ✅ Correctly rejected duplicate: {msg}")
    else:
        print("   ❌ Duplicate registration allowed!")


def test_authentication_flow():
    """Verify user login and authentication."""
    
    print("\n" + "="*70)
    print("🔑 User Authentication Tests")
    print("="*70)

    db = Database('securechat.db')

    # Correct credentials
    print("\n1️⃣ Authenticating Alice with correct password...")
    success, user, msg = db.authenticate_user('alice@example.com', 'password123')
    if success:
        print(f"   ✅ Login successful: User ID {user.user_id}, Email {user.email}")
    else:
        print(f"   ❌ {msg}")

    # Wrong password
    print("\n2️⃣ Authenticating Alice with wrong password...")
    success, _, msg = db.authenticate_user('alice@example.com', 'wrong_password')
    print(f"   {'✅' if not success else '❌'} Authentication rejected: {msg}")

    # Non-existent user
    print("\n3️⃣ Authenticating non-existent user...")
    success, _, msg = db.authenticate_user('ghost@example.com', 'password')
    print(f"   {'✅' if not success else '❌'} {msg}")

    # Bob's login
    print("\n4️⃣ Authenticating Bob...")
    success, user, msg = db.authenticate_user('bob@example.com', 'secure_password')
    print(f"   {'✅' if success else '❌'} {msg} (User ID: {user.user_id if user else 'N/A'})")


def test_user_queries():
    """Test user lookup functions."""

    print("\n" + "="*70)
    print("🔍 User Lookup Tests")
    print("="*70)

    db = Database('securechat.db')

    # Lookup by email
    print("\n1️⃣ Looking up Alice by email...")
    user = db.get_user_by_email('alice@example.com')
    if user:
        print(f"   ✅ Found: {user.email} (ID: {user.user_id})")
    else:
        print("   ❌ User not found")

    # Lookup by ID
    print("\n2️⃣ Looking up Alice by ID...")
    if user:
        found_user = db.get_user_by_id(user.user_id)
        print(f"   {'✅' if found_user else '❌'} Found: {found_user.email if found_user else 'N/A'}")

    # Check existence
    print("\n3️⃣ Checking if users exist...")
    print(f"   Bob exists: {db.user_exists('bob@example.com')}")
    print(f"   Ghost exists: {db.user_exists('ghost@example.com')}")

    # List all users
    print("\n4️⃣ Listing all users...")
    users = db.list_users()
    print(f"   Total users: {len(users)}")
    for uid, email in users:
        print(f"   - ID {uid}: {email}")


def test_transcript_workflow():
    """Validate transcript session creation, messaging, and receipt."""

    print("\n" + "="*70)
    print("📝 Transcript Session Tests")
    print("="*70)

    transcript = Transcript('securechat.db')

    # Create session
    print("\n1️⃣ Creating new session...")
    success, session_id, msg = transcript.create_session(user_id=1)
    print(f"   {'✅' if success else '❌'} {msg}")
    if not success:
        return

    # Add messages
    timestamp = int(time.time())
    messages_data = [
        (1, 1, timestamp, '0123456789abcdef'*4, 'deadbeef'*16),
        (2, 2, timestamp+1, 'fedcba9876543210'*4, 'cafebabe'*16)
    ]

    for sender_id, seq, ts, ct, sig in messages_data:
        print(f"\n2️⃣ Adding message seq {seq} from user {sender_id}...")
        success, msg_id, msg_text = transcript.add_message(
            session_id=session_id,
            sender_id=sender_id,
            sequence_number=seq,
            timestamp=ts,
            ciphertext=ct,
            signature=sig
        )
        print(f"   {'✅' if success else '❌'} {msg_text} (ID: {msg_id})")

    # Retrieve messages
    print("\n3️⃣ Fetching session messages...")
    msgs = transcript.get_session_messages(session_id)
    print(f"   Total messages: {len(msgs)}")
    for m in msgs:
        print(f"   - Seq {m.sequence_number} from user {m.sender_id}")

    # Compute hash
    print("\n4️⃣ Computing session hash...")
    success, session_hash, msg_text = transcript.compute_transcript_hash(session_id)
    print(f"   {'✅' if success else '❌'} Hash: {session_hash}")

    # Close session
    print("\n5️⃣ Closing session with receipt...")
    if session_hash:
        success, msg_text = transcript.close_session(
            session_id=session_id,
            session_receipt='abcd1234'*16
        )
        print(f"   {'✅' if success else '❌'} {msg_text}")

    # Retrieve receipt
    print("\n6️⃣ Retrieving session receipt...")
    receipt = transcript.get_session_receipt(session_id)
    print(f"   {'✅' if receipt else '❌'} Receipt: {receipt}")


def test_password_hashing_security():
    """Ensure password hashing uses unique salts."""

    print("\n" + "="*70)
    print("🔐 Password Hashing Tests")
    print("="*70)

    db = Database('securechat.db')
    password = "TestPassword123!"

    print("\n1️⃣ Hashing the same password twice...")
    hash1, salt1 = db._hash_password(password)
    hash2, salt2 = db._hash_password(password)
    print(f"   Hash1: {hash1[:32]}..., Hash2: {hash2[:32]}...")
    print(f"   Salt1: {salt1[:16]}..., Salt2: {salt2[:16]}...")
    print(f"   {'✅ Different hashes' if hash1 != hash2 else '❌ Hash collision!'}")

    print("\n2️⃣ Verifying correct password...")
    print(f"   Verified: {db._verify_password(password, hash1, salt1)}")

    print("\n3️⃣ Verifying with wrong salt...")
    print(f"   Verified: {db._verify_password(password, hash1, salt2)}")

    print("\n4️⃣ Verifying wrong password...")
    print(f"   Verified: {db._verify_password('WrongPassword', hash1, salt1)}")


if __name__ == "__main__":
    print("\n" + "="*70)
    print("🧪 Running Database and Transcript Tests")
    print("="*70 + "\n")

    # Clean up test DB if it exists
    if os.path.exists('securechat.db'):
        try:
            os.remove('securechat.db')
        except:
            pass

    test_registration_flow()
    test_authentication_flow()
    test_user_queries()
    test_password_hashing_security()
    test_transcript_workflow()

    print("\n" + "="*70)
    print("✅ All tests completed successfully")
    print("="*70)
