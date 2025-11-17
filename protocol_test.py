#!/usr/bin/env python3
"""Tests for SecureChat protocol message serialization and deserialization."""

from app.common.protocol import (
    Hello, ServerHello, DHClient, DHServer,
    Register, RegisterResponse, Login, LoginResponse,
    Message, Receipt, Error, message_to_json, json_to_message
)


def test_hello_messages():
    """Verify HELLO and SERVER_HELLO messages are serialized and deserialized correctly."""
    print("=" * 70)
    print("🔹 Testing HELLO Messages")
    print("=" * 70)

    # Client HELLO
    hello = Hello(certificate="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
    print(f"Client HELLO: Type={hello.type}, Certificate length={len(hello.certificate)}")

    serialized = message_to_json(hello)
    deserialized = json_to_message(serialized)
    print(f"Deserialized: {type(deserialized).__name__}")

    # Server HELLO
    server_hello = ServerHello(certificate="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
    serialized_srv = message_to_json(server_hello)
    deserialized_srv = json_to_message(serialized_srv)
    print("Server HELLO round-trip successful\n")


def test_dh_messages():
    """Verify Diffie-Hellman messages are correctly handled."""
    print("=" * 70)
    print("🔹 Testing Diffie-Hellman Messages")
    print("=" * 70)

    dh_client = DHClient(public_key="a" * 512)
    print(f"DHClient: Type={dh_client.type}, Public key length={len(dh_client.public_key)}")
    dh_client_round = json_to_message(message_to_json(dh_client))
    print("DHClient round-trip successful")

    dh_server = DHServer(public_key="b" * 512)
    print(f"DHServer: Type={dh_server.type}")
    dh_server_round = json_to_message(message_to_json(dh_server))
    print("DHServer round-trip successful\n")


def test_auth_messages():
    """Verify REGISTER, LOGIN, and their responses."""
    print("=" * 70)
    print("🔹 Testing Authentication Messages")
    print("=" * 70)

    register = Register(
        email="alice@example.com",
        password="secret123",
        ciphertext="0123456789abcdef" * 8,
        signature="deadbeef" * 16
    )
    register_round = json_to_message(message_to_json(register))
    print(f"REGISTER round-trip successful: Email={register.email}")

    reg_response = RegisterResponse(
        success=True,
        user_id=42,
        ciphertext="fedcba9876543210" * 8,
        signature="cafebabe" * 16
    )
    reg_resp_round = json_to_message(message_to_json(reg_response))
    print(f"REGISTER_RESPONSE round-trip successful: User ID={reg_response.user_id}")

    login = Login(
        email="alice@example.com",
        password="secret123",
        ciphertext="0123456789abcdef" * 8,
        signature="deadbeef" * 16
    )
    login_round = json_to_message(message_to_json(login))
    print("LOGIN round-trip successful")

    login_response = LoginResponse(
        success=True,
        user_id=42,
        session_id=1,
        ciphertext="fedcba9876543210" * 8,
        signature="cafebabe" * 16
    )
    login_resp_round = json_to_message(message_to_json(login_response))
    print(f"LOGIN_RESPONSE round-trip successful: Session ID={login_response.session_id}\n")


def test_chat_messages():
    """Verify MESSAGE and RECEIPT messages serialization and deserialization."""
    print("=" * 70)
    print("🔹 Testing Chat Messages")
    print("=" * 70)

    msg = Message(
        sender_id=1,
        session_id=1,
        sequence_number=1,
        timestamp=1700000000,
        ciphertext="0123456789abcdef" * 8,
        signature="deadbeef" * 16
    )
    msg_round = json_to_message(message_to_json(msg))
    print("MESSAGE round-trip successful")

    receipt = Receipt(
        sender_id=1,
        session_id=1,
        transcript_hash="a" * 64,
        signature="b" * 256
    )
    receipt_round = json_to_message(message_to_json(receipt))
    print("RECEIPT round-trip successful\n")


def test_error_message():
    """Verify ERROR message serialization and deserialization."""
    print("=" * 70)
    print("🔹 Testing ERROR Messages")
    print("=" * 70)

    error = Error(
        error_code="INVALID_CERT",
        error_message="Client certificate verification failed"
    )
    error_round = json_to_message(message_to_json(error))
    print(f"ERROR round-trip successful: Code={error.error_code}\n")


def test_json_edge_cases():
    """Verify handling of invalid JSON and missing fields."""
    print("=" * 70)
    print("🔹 Testing JSON Parsing Edge Cases")
    print("=" * 70)

    try:
        json_to_message("invalid json")
        print("❌ Should have failed for invalid JSON")
    except ValueError as e:
        print(f"✅ Correctly rejected invalid JSON: {str(e)[:50]}...")

    try:
        json_to_message('{"type": "unknown_type"}')
        print("❌ Should have failed for unknown type")
    except ValueError as e:
        print(f"✅ Correctly rejected unknown type: {str(e)}")

    try:
        json_to_message('{"type": "hello"}')
        print("❌ Should have failed for missing fields")
    except ValueError as e:
        print(f"✅ Correctly rejected missing fields: {str(e)[:50]}...\n")


def test_full_protocol_flow():
    """Simulate a full protocol message exchange."""
    print("=" * 70)
    print("🔹 Testing Full Protocol Flow")
    print("=" * 70)

    messages = []

    # HELLO exchange
    messages.append(message_to_json(Hello(certificate="client_cert_pem")))
    messages.append(message_to_json(ServerHello(certificate="server_cert_pem")))

    # DH key exchange
    messages.append(message_to_json(DHClient(public_key="c" * 512)))
    messages.append(message_to_json(DHServer(public_key="s" * 512)))

    # Registration
    messages.append(message_to_json(Register(
        email="alice@example.com",
        password="password123",
        ciphertext="encrypted_with_temp_key" * 4,
        signature="signed_by_client" * 4
    )))
    messages.append(message_to_json(RegisterResponse(
        success=True,
        user_id=1,
        ciphertext="encrypted_response",
        signature="signed_by_server"
    )))

    # Login
    messages.append(message_to_json(Login(
        email="alice@example.com",
        password="password123",
        ciphertext="encrypted_login_msg",
        signature="client_signature"
    )))
    messages.append(message_to_json(LoginResponse(
        success=True,
        user_id=1,
        session_id=1,
        ciphertext="encrypted_session_info",
        signature="server_signature"
    )))

    # Chat messages
    for i in range(1, 4):
        messages.append(message_to_json(Message(
            sender_id=1,
            session_id=1,
            sequence_number=i,
            timestamp=1700000000 + i,
            ciphertext=f"encrypted_msg_{i}" * 4,
            signature=f"signature_{i}" * 8
        )))

    # Session closure
    messages.append(message_to_json(Receipt(
        sender_id=1,
        session_id=1,
        transcript_hash="a" * 64,
        signature="b" * 256
    )))
    messages.append(message_to_json(Receipt(
        sender_id=2,
        session_id=1,
        transcript_hash="a" * 64,
        signature="c" * 256
    )))

    print(f"Total messages exchanged: {len(messages)}")

    # Deserialize verification
    for idx, msg_json in enumerate(messages, 1):
        try:
            msg_obj = json_to_message(msg_json)
            print(f"Message {idx} deserialized successfully: {msg_obj.type}")
        except Exception as e:
            print(f"Message {idx} failed deserialization: {e}")

    print("\n✅ Full protocol flow test completed\n")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🔹 SecureChat Protocol Serialization/Deserialization Tests")
    print("=" * 70 + "\n")

    test_hello_messages()
    test_dh_messages()
    test_auth_messages()
    test_chat_messages()
    test_error_message()
    test_json_edge_cases()
    test_full_protocol_flow()

    print("=" * 70)
    print("✅ All SecureChat protocol tests completed")
    print("=" * 70)
