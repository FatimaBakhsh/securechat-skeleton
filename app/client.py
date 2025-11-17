"""
Secure Chat Client

- Connects to the server.
- Handles user registration/login.
- Runs secure chat sessions with transcript logging.
"""

import socket
import sys
import getpass
from typing import Optional
from cryptography import x509

# --- Project imports ---
from app.crypto import pki, dh as dh_crypto, aes, sign
from app.common import protocol, utils
from app.storage.transcript import Transcript

# --- Networking helpers ---
def send_bytes(conn: socket.socket, data: bytes):
    try:
        conn.sendall(len(data).to_bytes(4, 'big') + data)
    except Exception as e:
        print(f"[Network Error] Send failed: {e}")
        raise

def recv_bytes(conn: socket.socket) -> Optional[bytes]:
    try:
        len_bytes = conn.recv(4)
        if not len_bytes: return None
        msg_len = int.from_bytes(len_bytes, 'big')
        data = b""
        while len(data) < msg_len:
            packet = conn.recv(msg_len - len(data))
            if not packet: return None
            data += packet
        return data
    except Exception as e:
        print(f"[Network Error] Receive failed: {e}")
        return None

def send_message(conn: socket.socket, msg_model: protocol.BaseModel):
    send_bytes(conn, protocol.serialize_message(msg_model))

def recv_message(conn: socket.socket) -> Optional[protocol.AnyMessage]:
    data = recv_bytes(conn)
    if not data: return None
    return protocol.parse_message(data)

# --- Client ---
class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.ca_cert = pki.load_ca_cert()
            self.client_cert, self.client_key = pki.load_identity("certs/client")
            self.client_cn = pki.get_certificate_cn(self.client_cert)
            print(f"Client CN: {self.client_cn}")
        except Exception as e:
            print(f"Fatal: Cannot load client identity. {e}")
            sys.exit(1)

    def connect(self):
        try:
            print(f"Connecting to {self.host}:{self.port}...")
            self.sock.connect((self.host, self.port))
            print("Connected.")
        except Exception as e:
            print(f"Error: Connection failed: {e}")
            sys.exit(1)

    def run(self):
        server_cn = "unknown"
        transcript = None
        try:
            self.connect()
            server_cert = self.perform_pki_handshake()
            server_cn = pki.get_certificate_cn(server_cert)
            print(f"Server certificate verified. CN={server_cn}")

            k_auth = self.perform_auth_key_exchange()
            if not self.perform_authentication(k_auth):
                raise ValueError("Authentication failed.")

            k_chat = self.perform_chat_key_exchange()
            transcript = Transcript(peer_name="client", peer_cn=server_cn)
            self.run_chat_session(k_chat, server_cn, server_cert, transcript)

        except Exception as e:
            print(f"Error: {e}")
        finally:
            if transcript:
                h, path = transcript.finalize()
                print(f"Transcript saved: {path}, hash={h}")
            self.sock.close()
            print("Connection closed.")

    # --- PKI / DH / Auth ---
    def perform_pki_handshake(self) -> x509.Certificate:
        hello = protocol.HelloModel(
            client_cert=utils.cert_to_b64_str(self.client_cert),
            nonce=utils.b64e(utils.generate_nonce())
        )
        send_message(self.sock, hello)

        msg = recv_message(self.sock)
        if not isinstance(msg, protocol.ServerHelloModel):
            raise ValueError("Expected ServerHello")
        server_cert = utils.b64_str_to_cert(msg.server_cert)
        pki.verify_certificate(server_cert, self.ca_cert, "server.local")
        return server_cert

    def _perform_dh_exchange(self) -> bytes:
        priv, pub_val = dh_crypto.generate_dh_keypair()
        send_message(self.sock, protocol.DhClientModel(
            g=dh_crypto._g,
            p=dh_crypto._p,
            A=pub_val
        ))

        msg = recv_message(self.sock)
        if not isinstance(msg, protocol.DhServerModel):
            raise ValueError("Expected DhServerModel")
        shared_secret = dh_crypto.compute_shared_secret(priv, msg.B)
        return dh_crypto.derive_aes_key(shared_secret)

    perform_auth_key_exchange = _perform_dh_exchange
    perform_chat_key_exchange = _perform_dh_exchange

    def perform_authentication(self, k_auth: bytes) -> bool:
        action = input("Do you want to (r)egister or (l)ogin? ").strip().lower()
        if action == "r":
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            salt = utils.generate_nonce(16)
            pwd_hash = utils.sha256_hex(salt + password.encode())
            model = protocol.RegisterModel(
                email=email,
                username=username,
                pwd=utils.b64e(pwd_hash.encode()),
                salt=utils.b64e(salt)
            )
        elif action == "l":
            email = input("Email: ").strip()
            password = getpass.getpass("Password: ")
            model = protocol.LoginModel(
                email=email,
                pwd=utils.b64e(password.encode()),
                nonce=utils.b64e(utils.generate_nonce(16))
            )
        else:
            print("Invalid action.")
            return False

        payload = aes.encrypt(k_auth, protocol.serialize_message(model))
        send_bytes(self.sock, payload)
        response = recv_message(self.sock)
        if isinstance(response, protocol.SuccessModel):
            print(f"Success: {response.message}")
            return True
        if isinstance(response, protocol.ErrorModel):
            print(f"Error: {response.message}")
        return False

    # --- Chat session ---
    def run_chat_session(self, k_chat: bytes, server_cn: str, server_cert: x509.Certificate, transcript: Transcript):
        server_seq = 0
        client_seq = 0
        print(f"--- Chat session with {server_cn} started ---")
        print("Waiting for server... (Type '/quit' to exit)")

        try:
            while True:
                # Receive server message
                msg = recv_message(self.sock)
                if not msg:
                    print("Server disconnected.")
                    break
                if not isinstance(msg, protocol.MsgModel):
                    raise ValueError("Expected MsgModel from server")
                if msg.seqno <= server_seq:
                    raise ValueError("REPLAY attack detected")
                server_seq = msg.seqno
                hash_verify = utils.sha256_bytes(f"{msg.seqno}{msg.ts}{msg.ct}".encode())
                if not sign.verify_signature(server_cert, hash_verify, utils.b64d(msg.sig)):
                    raise ValueError("Signature verification failed")
                transcript.log_message(server_cn, msg.seqno, msg.ts, msg.ct, msg.sig)
                print(f"({server_cn}) > {aes.decrypt(k_chat, utils.b64d(msg.ct)).decode()}")

                # Send client message
                client_plaintext = input(f"({self.client_cn}) > ")
                if client_plaintext == "/quit":
                    break
                client_seq += 1
                ts = utils.now_ms()
                ct_b64 = utils.b64e(aes.encrypt(k_chat, client_plaintext.encode()))
                sig_b64 = utils.b64e(sign.sign_hash(self.client_key, utils.sha256_bytes(f"{client_seq}{ts}{ct_b64}".encode())))
                transcript.log_message(self.client_cn, client_seq, ts, ct_b64, sig_b64)
                send_message(self.sock, protocol.MsgModel(seqno=client_seq, ts=ts, ct=ct_b64, sig=sig_b64))

        except Exception as e:
            print(f"[Chat Error] {e}")
            try:
                send_message(self.sock, protocol.ErrorModel(code="CHAT_ERROR", message=str(e)))
            except: pass

if __name__ == "__main__":
    client = Client("127.0.0.1", 12345)
    client.run()
