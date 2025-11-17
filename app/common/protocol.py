"""
Pydantic models for secure chat protocol messages.

Includes:
- handshake, registration/login
- Diffie-Hellman key exchange
- encrypted messages and receipts
- generic success/error messages
- helpers for parsing/serialization
"""

import json
from pydantic import BaseModel
from typing import Literal, Union, get_args

# Handshake messages

class HelloMsg(BaseModel):
    """Client -> Server first handshake."""
    type: Literal["hello"] = "hello"
    client_cert: str
    nonce: str

class ServerHelloMsg(BaseModel):
    """Server -> Client handshake response."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str
    nonce: str

# Registration/Login

class RegisterMsg(BaseModel):
    """Client -> Server encrypted registration request."""
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str
    salt: str

class LoginMsg(BaseModel):
    """Client -> Server encrypted login request."""
    type: Literal["login"] = "login"
    email: str
    pwd: str
    nonce: str

# Diffie-Hellman key agreement

class DhClientMsg(BaseModel):
    """Client -> Server DH key exchange initiation."""
    type: Literal["dh_client"] = "dh_client"
    g: int
    p: int
    A: int

class DhServerMsg(BaseModel):
    """Server -> Client DH key exchange response."""
    type: Literal["dh_server"] = "dh_server"
    B: int

# Encrypted chat message

class ChatMsg(BaseModel):
    """Encrypted chat message between client/server."""
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int
    ct: str
    sig: str

# Receipt message

class ReceiptMsg(BaseModel):
    """Signed transcript receipt."""
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str

# Generic success/error

class ErrorMsg(BaseModel):
    """Generic error response."""
    type: Literal["error"] = "error"
    code: str
    message: str

class SuccessMsg(BaseModel):
    """Generic success/acknowledgment."""
    type: Literal["success"] = "success"
    message: str = "Operation successful"

# Union of all message types
AnyMsg = Union[
    HelloMsg,
    ServerHelloMsg,
    RegisterMsg,
    LoginMsg,
    DhClientMsg,
    DhServerMsg,
    ChatMsg,
    ReceiptMsg,
    ErrorMsg,
    SuccessMsg
]

# Map "type" field to model class
MSG_TYPE_MAP = {cls.model_fields["type"].default: cls for cls in get_args(AnyMsg)}

def parse_msg(raw_bytes: bytes) -> AnyMsg:
    """Convert raw network bytes into a validated Pydantic message."""
    try:
        json_str = raw_bytes.decode('utf-8')
        msg_dict = json.loads(json_str)
    except Exception:
        raise ValueError(f"Invalid JSON: {raw_bytes.decode('utf-8', errors='ignore')}")

    msg_type = msg_dict.get("type")
    if not msg_type:
        raise ValueError("Missing 'type' field in message.")

    model_cls = MSG_TYPE_MAP.get(msg_type)
    if not model_cls:
        raise ValueError(f"Unknown message type: '{msg_type}'")

    try:
        return model_cls.model_validate(msg_dict)
    except Exception as e:
        raise ValueError(f"Validation failed for '{msg_type}': {e}")

def serialize_msg(model: BaseModel) -> bytes:
    """Convert a Pydantic message model into bytes for network transmission."""
    json_str = model.model_dump_json()
    return json_str.encode('utf-8')
