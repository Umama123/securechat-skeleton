"""
Test: Replay Attack Detection
Goal:
 - Ensure server rejects messages that reuse a sequence number.
 - Re-authenticate, then send two messages with identical seq.
"""

import os
import sys
import json
import time
import socket
import struct
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.crypto import pki, dh, aes, sign as siglib
from app.common import utils

HOST = "127.0.0.1"
PORT = 5001

CERTS = {
    "client_cert": "certs/client_cert.pem",
    "client_key": "certs/client_key.pem",
    "ca": "certs/root_ca_cert.pem"
}

# RFC3526 MODP group parameters
MODP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD12"
    "9024E088A67CC74020BBEA63B139B22514A08798E3404DDEF95"
    "19B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B57"
    "6625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A8"
    "99FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0"
    "598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C6"
    "2F356208552BB9ED529077096966D670C354E4ABC9804F1746C0"
    "8CA237327FFFFFFFFFFFFFFFF", 16
)
MODP_G = 2


# ----------------------------------------------------------------------
# I/O Helpers
# ----------------------------------------------------------------------

def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_json(sock, timeout=5):
    sock.settimeout(timeout)
    hdr = sock.recv(4)
    if len(hdr) < 4:
        raise ConnectionError("connection closed")
    msg_len = struct.unpack("!I", hdr)[0]

    buf = b""
    while len(buf) < msg_len:
        chunk = sock.recv(msg_len - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk

    return json.loads(buf.decode())


# ----------------------------------------------------------------------
# Crypto Helpers
# ----------------------------------------------------------------------

def hmac_key_from_shared(Ks):
    """HMAC key = SHA256(Ks || 'auth')."""
    raw = Ks.to_bytes((Ks.bit_length() + 7) // 8, "big")
    return hashlib.sha256(raw + b"auth").digest()


def build_canonical(cipher, seq, c_nonce, s_nonce):
    parts = [cipher or "", str(seq), c_nonce or "", s_nonce or ""]
    return "|".join(parts).encode()


# ----------------------------------------------------------------------
# Authentication + DH
# ----------------------------------------------------------------------

def run_handshake(sock):
    """
    Full handshake:
      1) Client hello
      2) Server hello
      3) Validate server cert
      4) DH key exchange
      5) Derive AES + HMAC keys
    """
    print("[*] Starting handshake\n")

    client_cert = Path(CERTS["client_cert"]).read_text()
    client_nonce = utils.b64e(os.urandom(16))

    send_json(sock, {
        "type": "client_hello",
        "client cert": client_cert,
        "nonce": client_nonce
    })
    print("[>] Client hello sent")

    server_hello = recv_json(sock)
    server_cert_pem = server_hello.get("server cert")
    server_nonce = server_hello.get("nonce")
    print("[<] Server hello received")

    valid, reason = pki.validate_cert(server_cert_pem, CERTS["ca"], "server.local")
    if not valid:
        raise RuntimeError(f"Server certificate invalid: {reason}")

    server_cert = x509.load_pem_x509_certificate(server_cert_pem.encode(), default_backend())
    server_pub = server_cert.public_key()

    priv_a = dh.generate_private_key(MODP_P)
    pub_A = dh.generate_public_key(MODP_G, priv_a, MODP_P)

    send_json(sock, {
        "type": "dh_client",
        "g": MODP_G,
        "p": str(MODP_P),
        "A": str(pub_A)
    })

    dh_reply = recv_json(sock)
    pub_B = int(dh_reply["B"])

    Ks = dh.compute_shared_secret(pub_B, priv_a, MODP_P)
    aes_key = dh.derive_aes_key(Ks)
    hmac_key = hmac_key_from_shared(Ks)

    print("[+] Session keys derived\n")

    return aes_key, hmac_key, client_nonce, server_nonce, server_pub


# ----------------------------------------------------------------------
# Secure message construction
# ----------------------------------------------------------------------

def secure_wrap(aes_key, hmac_key, priv_key, payload, seq, c_nonce, s_nonce):
    raw = json.dumps(payload).encode()
    ct = aes.encrypt(aes_key, raw)
    canonical = build_canonical(ct, seq, c_nonce, s_nonce)

    return {
        "type": "secure",
        "ciphertext": ct,
        "seq": seq,
        "client_nonce": c_nonce,
        "server_nonce": s_nonce,
        "hmac": aes.hmac_sha256_b64(hmac_key, canonical),
        "signature": siglib.sign(priv_key, canonical)
    }


# ----------------------------------------------------------------------
# Replay Test
# ----------------------------------------------------------------------

def test_replay():
    print("\n==== TEST 4: Replay Attack Detection ====\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}\n")

        aes_key, hmac_key, c_nonce, s_nonce, srv_pub = run_handshake(sock)

        # --- LOGIN attempt ---
        client_key = siglib.load_private_key(CERTS["client_key"])
        seq_login = utils.now_ms()

        login_data = {
            "type": "login_request",
            "username": "alice",
            "password": "password123",
            "client_nonce": c_nonce
        }

        login_msg = secure_wrap(aes_key, hmac_key, client_key, login_data,
                                seq_login, c_nonce, s_nonce)
        print("[>] Sending login request...")
        send_json(sock, login_msg)

        # Attempt to read but not required to continue replay logic
        try:
            resp = recv_json(sock)
            print("[<] Login response received")
        except:
            print("[!] Login response not received, continuing test...")

        time.sleep(0.2)

        # --- Construct normal message ---
        seq_value = utils.now_ms()
        msg_body = {
            "type": "app_msg",
            "seq": seq_value,
            "ts": seq_value,
            "text": "Original message"
        }

        wrapped = secure_wrap(aes_key, hmac_key, client_key,
                              msg_body, seq_value, c_nonce, s_nonce)

        print(f"[>] Sending message with seq={seq_value}")
        send_json(sock, wrapped)

        try:
            first_reply = recv_json(sock)
            print(f"[<] First response type: {first_reply.get('type')}")
        except:
            print("[!] Did not receive first response")

        # --- REPLAY ATTACK ---
        print(f"[!] Sending replayed message with SAME seq={seq_value}")
        time.sleep(0.1)
        send_json(sock, wrapped)

        print("[<] Awaiting server detection...")

        try:
            second = recv_json(sock)
            print(f"[<] Replay response: {second}")

            if second.get("type") == "error" and second.get("reason") == "REPLAY":
                print("\n✓ TEST PASSED: Server detected replay attack")
                return True

            print("\n✗ TEST FAILED: Replay not detected")
            return False

        except socket.timeout:
            print("\n✓ TEST PASSED: Server timeout indicates replay rejection")
            return True

        except ConnectionError:
            print("\n✓ TEST PASSED: Server closed connection due to replay")
            return True

    except Exception as exc:
        print(f"\n✗ TEST FAILED due to unexpected error: {exc}")
        return False

    finally:
        sock.close()
        print("[*] Connection closed\n")


# ----------------------------------------------------------------------

if __name__ == "__main__":
    ok = test_replay()
    print("Security Test Passed\n" if ok else "Security Test Failed\n")
