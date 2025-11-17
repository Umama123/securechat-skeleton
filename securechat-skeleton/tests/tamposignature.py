"""
Test: Tampered Signature Detection (Refactored)
Expected: Server should detect corrupted signature and respond with SIG_FAIL
"""
import sys
import os
import json
import socket
import struct
from pathlib import Path
import hashlib
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from app.crypto import dh, aes, sign as sign_mod
from app.common import utils

# Server and certificate paths
HOST, PORT = '127.0.0.1', 5001
CLIENT_CERT_PATH = "certs/client_cert.pem"
CLIENT_KEY_PATH = "certs/client_key.pem"
ROOT_CA_CERT_PATH = "certs/root_ca_cert.pem"

# Diffie-Hellman parameters
MODP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA237327FFFFFFFFFFFFFFFF", 16
)
MODP_G = 2

# Example ciphertext (from user input)
USER_CIPHERTEXT = "QBKUQQQVQVQMKUQMQBQRQVKUQLQPQHQBQCQL"

def send_msg(sock, data):
    """Send JSON object with 4-byte length prefix."""
    payload = json.dumps(data).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_msg(sock):
    """Receive JSON object with 4-byte length prefix."""
    header = sock.recv(4)
    if len(header) < 4:
        raise ConnectionError("connection closed")
    length = struct.unpack("!I", header)[0]
    buffer = b""
    while len(buffer) < length:
        chunk = sock.recv(length - len(buffer))
        if not chunk:
            raise ConnectionError("connection closed")
        buffer += chunk
    return json.loads(buffer.decode("utf-8"))

def hmac_key_from_Ks(Ks: int) -> bytes:
    return hashlib.sha256(Ks.to_bytes((Ks.bit_length() + 7) // 8, "big") + b"auth").digest()

def canonicalize(ciphertext, seq, client_nonce, server_nonce) -> bytes:
    return "|".join([ciphertext, str(seq), client_nonce, server_nonce]).encode("utf-8")

def test_tampered_signature():
    print("\n[TEST] Tampered Signature Detection\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"[+] Connected to server {HOST}:{PORT}")

    try:
        # Load client certificate and create hello
        client_cert = Path(CLIENT_CERT_PATH).read_text()
        client_nonce = utils.b64e(os.urandom(16))
        hello_msg = {"type": "client hello", "client cert": client_cert, "nonce": client_nonce}
        send_msg(sock, hello_msg)
        print("[>] Sent client hello")

        # Receive server hello
        server_hello = recv_msg(sock)
        server_nonce = server_hello.get("nonce")
        print("[<] Received server hello")

        # Diffie-Hellman key exchange
        priv_key = dh.generate_private_key(MODP_P)
        pub_key = dh.generate_public_key(MODP_G, priv_key, MODP_P)
        dh_client = {"type": "dh_client", "g": MODP_G, "p": str(MODP_P), "A": str(pub_key)}
        send_msg(sock, dh_client)
        dh_server = recv_msg(sock)
        B = int(dh_server.get("B"))

        Ks = dh.compute_shared_secret(B, priv_key, MODP_P)
        aes_key = dh.derive_aes_key(Ks)
        hmac_key = hmac_key_from_Ks(Ks)
        print("[+] Derived session keys")

        # Use user-provided ciphertext instead of encrypting
        seq = utils.now_ms()
        canon_bytes_data = canonicalize(USER_CIPHERTEXT, seq, client_nonce, server_nonce)
        mac = aes.hmac_sha256_b64(hmac_key, canon_bytes_data)

        # Sign the canonicalized bytes
        priv = sign_mod.load_private_key(CLIENT_KEY_PATH)
        signature = sign_mod.sign(priv, canon_bytes_data)

        # Tamper with the signature
        tampered_signature = signature[:-8] + "XXXXXXXX"

        wire_msg = {
            "type": "secure",
            "ciphertext": USER_CIPHERTEXT,
            "seq": seq,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "hmac": mac,
            "signature": tampered_signature
        }

        send_msg(sock, wire_msg)
        print("[>] Sent message with tampered signature")

        # Wait for server response
        response = recv_msg(sock)
        print(f"[<] Received response: {response}")

        if response.get("type") == "error" and response.get("reason") == "SIG_FAIL":
            print("\n[PASS] Server correctly detected tampered signature")
            return True
        else:
            print("\n[FAIL] Server did not detect tampering!")
            return False

    except ConnectionError:
        print("\n[PASS] Connection closed by server (tampered signature rejected)")
        return True
    finally:
        sock.close()
        print("[*] Connection closed\n")

if __name__ == "__main__":
    if test_tampered_signature():
        print("Security Test Passed: Tampered signatures are detected")
    else:
        print("Security Test Failed: System is vulnerable")
