"""
Secure Chat Server

- Listens for client connections.
- Handles PKI, DH key exchanges, registration/login.
- Runs secure chat sessions with transcript logging.
"""

import socket
import threading
import sys
import os
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- Project imports ---
from app.crypto import pki, dh as dh_crypto, aes, sign
from app.common import protocol, utils
from app.storage.transcript import Transcript

# --- Database ---
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv
load_dotenv()

class Database:
    """Database operations: register, login, get salt."""
    
    def __init__(self):
        self.db_config = {
            'host': os.getenv('MYSQL_HOST', '127.0.0.1'),
            'port': os.getenv('MYSQL_PORT', '3306'),
            'user': os.getenv('MYSQL_USER'),
            'password': os.getenv('MYSQL_PASSWORD'),
            'database': os.getenv('MYSQL_DATABASE')
        }

    def _get_connection(self):
        try:
            return mysql.connector.connect(**self.db_config)
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("DB access denied. Check credentials.")
            else:
                print(f"[DB Error] Connection failed: {err}")
            return None

    def register_user(self, email: str, username: str, pwd_hash_hex: str, salt_bytes: bytes) -> bool:
        conn = self._get_connection()
        if not conn: return False
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, username, pwd_hash, salt) VALUES (%s, %s, %s, %s)",
                (email, username, pwd_hash_hex, salt_bytes)
            )
            conn.commit()
            return True
        except mysql.connector.Error as err:
            print(f"[DB Error] Registration failed: {err}")
            return False
        finally:
            if conn: conn.close()

    def get_user_salt(self, email: str) -> Optional[bytes]:
        conn = self._get_connection()
        if not conn: return None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            if result:
                return result[0] if isinstance(result[0], bytes) else bytes.fromhex(result[0])
            return None
        except mysql.connector.Error as err:
            print(f"[DB Error] Get salt failed: {err}")
            return None
        finally:
            if conn: conn.close()

    def check_login(self, email: str, password: str) -> Optional[str]:
        conn = self._get_connection()
        if not conn: return None
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT username, pwd_hash, salt FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            if result:
                computed_hash = utils.sha256_hex(result['salt'] + password.encode())
                if computed_hash == result['pwd_hash']:
                    return result['username']
            return None
        except mysql.connector.Error as err:
            print(f"[DB Error] Login failed: {err}")
            return None
        finally:
            if conn: conn.close()

# --- Networking helpers ---
def send_bytes(conn: socket.socket, data: bytes):
    try:
        conn.sendall(len(data).to_bytes(4, 'big') + data)
    except Exception as e:
        print(f"[Network Error] Send failed: {e}")

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

# --- Server ---
class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.db = Database()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.ca_cert = pki.load_ca_cert()
            self.server_cert, self.server_key = pki.load_identity("certs/server")
            self.server_cn = pki.get_certificate_cn(self.server_cert)
        except Exception as e:
            print(f"Fatal: Cannot load server identity. {e}")
            sys.exit(1)

    def run(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        try:
            while True:
                conn, addr = self.sock.accept()
                print(f"[+] Connection from {addr[0]}:{addr[1]}")
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
        except KeyboardInterrupt:
            print("Server shutting down.")
        finally:
            self.sock.close()

    def handle_client(self, conn: socket.socket):
        client_cn = "unknown"
        transcript = None
        try:
            client_cert = self.perform_pki_handshake(conn)
            client_cn = pki.get_certificate_cn(client_cert)

            k_auth = self.perform_auth_key_exchange(conn)
            username = self.perform_authentication(conn, k_auth)

            k_chat = self.perform_chat_key_exchange(conn)
            transcript = Transcript(peer_name="server", peer_cn=client_cn)
            self.run_chat_session(conn, client_cn, client_cert, k_chat, transcript)
        except Exception as e:
            print(f"[{client_cn}] Error: {e}")
        finally:
            if transcript:
                hash_hex, path = transcript.finalize()
                print(f"[{client_cn}] Transcript saved: {path}, hash: {hash_hex}")
            conn.close()
            print(f"[-] Connection from {client_cn} closed.")

    # --- PKI / DH / Auth functions ---
    def perform_pki_handshake(self, conn: socket.socket) -> x509.Certificate:
        msg = recv_message(conn)
        if not isinstance(msg, protocol.HelloModel):
            raise ValueError("Expected 'hello' message")
        client_cert = utils.b64_str_to_cert(msg.client_cert)
        pki.verify_certificate(client_cert, self.ca_cert, "client.local")
        send_message(conn, protocol.ServerHelloModel(
            server_cert=utils.cert_to_b64_str(self.server_cert),
            nonce=utils.b64e(utils.generate_nonce())
        ))
        return client_cert

    def _perform_dh_exchange(self, conn: socket.socket) -> bytes:
        msg = recv_message(conn)
        if not isinstance(msg, protocol.DhClientModel):
            raise ValueError("Expected 'dh_client' message")
        priv, pub_val = dh_crypto.generate_dh_keypair()
        shared_secret = dh_crypto.compute_shared_secret(priv, msg.A)
        send_message(conn, protocol.DhServerModel(B=pub_val))
        return dh_crypto.derive_aes_key(shared_secret)

    perform_auth_key_exchange = _perform_dh_exchange
    perform_chat_key_exchange = _perform_dh_exchange

    def perform_authentication(self, conn: socket.socket, k_auth: bytes) -> str:
        encrypted_data = recv_bytes(conn)
        decrypted_bytes = aes.decrypt(k_auth, encrypted_data)
        auth_msg = protocol.parse_message(decrypted_bytes)

        if isinstance(auth_msg, protocol.RegisterModel):
            pwd_hash_hex = utils.b64d(auth_msg.pwd).decode()
            salt_bytes = utils.b64d(auth_msg.salt)
            if self.db.register_user(auth_msg.email, auth_msg.username, pwd_hash_hex, salt_bytes):
                send_message(conn, protocol.SuccessModel("Registration successful"))
                return auth_msg.username
            raise ValueError("Registration failed")
        elif isinstance(auth_msg, protocol.LoginModel):
            password = utils.b64d(auth_msg.pwd).decode()
            username = self.db.check_login(auth_msg.email, password)
            if username:
                send_message(conn, protocol.SuccessModel("Login successful"))
                return username
            raise ValueError("Login failed")
        else:
            raise ValueError("Expected register/login message")

    def run_chat_session(self, conn: socket.socket, client_cn: str, client_cert: x509.Certificate, k_chat: bytes, transcript: Transcript):
        server_seq = 0
        client_seq = 0
        print(f"--- Chat session started with {client_cn} ---")
        try:
            while True:
                server_plaintext = input(f"({self.server_cn}) > ")
                if server_plaintext == "/quit":
                    break

                server_seq += 1
                ts = utils.now_ms()
                ct_b64 = utils.b64e(aes.encrypt(k_chat, server_plaintext.encode()))
                sig_b64 = utils.b64e(sign.sign_hash(self.server_key, utils.sha256_bytes(f"{server_seq}{ts}{ct_b64}".encode())))
                transcript.log_message(self.server_cn, server_seq, ts, ct_b64, sig_b64)
                send_message(conn, protocol.MsgModel(seqno=server_seq, ts=ts, ct=ct_b64, sig=sig_b64))

                print(f"Waiting for {client_cn}...")
                client_msg = recv_message(conn)
                if not client_msg: break
                if not isinstance(client_msg, protocol.MsgModel): raise ValueError("Expected MsgModel")
                if client_msg.seqno <= client_seq: raise ValueError("REPLAY attack detected")
                client_seq = client_msg.seqno

                hash_verify = utils.sha256_bytes(f"{client_msg.seqno}{client_msg.ts}{client_msg.ct}".encode())
                if not sign.verify_signature(client_cert, hash_verify, utils.b64d(client_msg.sig)):
                    raise ValueError("Signature verification failed")

                transcript.log_message(client_cn, client_msg.seqno, client_msg.ts, client_msg.ct, client_msg.sig)
                print(f"({client_cn}) > {aes.decrypt(k_chat, utils.b64d(client_msg.ct)).decode()}")

        except Exception as e:
            print(f"[Chat Error] {e}")
            try:
                send_message(conn, protocol.ErrorModel(code="CHAT_ERROR", message=str(e)))
            except: pass

if __name__ == "__main__":
    server = Server("127.0.0.1", 12345)
    server.run()
