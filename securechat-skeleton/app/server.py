import os, socket, json, struct, threading, hashlib
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.crypto import dh, aes, sign as sign_mod, pki
from app.common import utils
from app.storage.transcript import Transcript
from app.storage.db import verify_user, register_user

HOST = '127.0.0.1'
PORT = 5001
SERVER_CERT = "certs/server_cert.pem"
SERVER_KEY = "certs/server_key.pem"
ROOT_CA = "certs/root_ca_cert.pem"

MODP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA237327FFFFFFFFFFFFFFFF",
    16
)
MODP_G = 2

active_sessions = {}

def send(sock, obj):
    data = json.dumps(obj).encode('utf-8')
    sock.sendall(struct.pack('!I', len(data)) + data)

def recv(sock, timeout=None):
    if timeout: sock.settimeout(timeout)
    header = sock.recv(4)
    if len(header) < 4: raise ConnectionError("closed")
    length = struct.unpack('!I', header)[0]
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk: raise ConnectionError("closed")
        payload += chunk
    return json.loads(payload.decode())

def load_pem(path):
    return Path(path).read_text() if Path(path).exists() else None

def derive_hmac(Ks):
    return hashlib.sha256(Ks.to_bytes((Ks.bit_length()+7)//8,'big') + b"auth").digest()

def canon_bytes(cipher, seq, client_nonce, server_nonce):
    return "|".join([cipher or "", str(seq), client_nonce or "", server_nonce or ""]).encode()

class ChatSession:
    """Represents an active encrypted chat session with a client"""
    def __init__(self, conn, username, aes_key, hmac_key, client_nonce, server_nonce, client_pub, server_priv, transcript):
        self.conn = conn
        self.username = username
        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.client_nonce = client_nonce
        self.server_nonce = server_nonce
        self.client_pub = client_pub
        self.server_priv = server_priv
        self.transcript = transcript
        self.last_seq = None
        self.active = True
        self.lock = threading.Lock()

    def send_encrypted(self, text):
        with self.lock:
            if not self.active: return False
            try:
                seq = utils.now_ms()
                msg = {"type":"app_msg","seq":seq,"ts":utils.now_ms(),"text":text}
                ct = aes.encrypt(self.aes_key, json.dumps(msg).encode())
                canon = canon_bytes(ct, seq, self.client_nonce, self.server_nonce)
                mac = aes.hmac_sha256_b64(self.hmac_key, canon)
                sig = sign_mod.sign(self.server_priv, canon)
                send(self.conn, {"type":"secure","ciphertext":ct,"seq":seq,"client_nonce":self.client_nonce,
                                 "server_nonce":self.server_nonce,"hmac":mac,"signature":sig})
                self.last_seq = seq
                return True
            except Exception as e:
                print(f"[!] Failed to send message: {e}")
                return False

def handle_client(conn, addr):
    try:
        session_id = f"{addr[0]}_{addr[1]}"
        transcript = Transcript(session_id=session_id)

        # Phase 1: Certificate exchange
        client_hello = recv(conn)
        c_cert_pem = client_hello.get("client cert")
        c_nonce = client_hello.get("nonce")
        transcript.append(0, {"event":"client_hello"})

        client_pub = None
        if c_cert_pem:
            ok, reason = pki.validate_cert(c_cert_pem, ROOT_CA, "client.local")
            if not ok:
                send(conn, {"type":"error","reason":"BAD_CERT"}); conn.close(); return
            client_pub = x509.load_pem_x509_certificate(c_cert_pem.encode(), default_backend()).public_key()

        s_cert_pem = load_pem(SERVER_CERT)
        s_nonce = utils.b64e(os.urandom(16))
        send(conn, {"type":"server_hello","server cert":s_cert_pem,"nonce":s_nonce})
        transcript.append(1, {"event":"server_hello"})

        # Phase 2: Diffie-Hellman
        dh_client = recv(conn)
        A = int(dh_client.get("A"))
        b = dh.generate_private_key(MODP_P)
        B = dh.generate_public_key(MODP_G, b, MODP_P)
        send(conn, {"type":"dh_server","B":str(B)})
        transcript.append(2, {"event":"dh_exchange","client_A":A,"server_B":B})

        Ks = dh.compute_shared_secret(A, b, MODP_P)
        aes_key = dh.derive_aes_key(Ks)
        hmac_key = derive_hmac(Ks)

        # Phase 3: Auth
        login_msg = recv(conn)
        ct, seq, mac, sig = login_msg["ciphertext"], login_msg["seq"], login_msg["hmac"], login_msg["signature"]
        canon = canon_bytes(ct, seq, c_nonce, s_nonce)
        if not aes.verify_hmac_sha256_b64(hmac_key, canon, mac) or not sign_mod.verify(client_pub, canon, sig):
            send(conn, {"type":"error","reason":"AUTH_FAIL"}); conn.close(); return

        data = json.loads(aes.decrypt(aes_key, ct).decode())
        if data.get("type")=="login_request":
            username, password = data.get("username"), data.get("password")
            success = verify_user(username, password)
            msg_text = f"Welcome back, {username}!" if success else "Invalid credentials"
        elif data.get("type")=="register_request":
            username, password, email = data.get("username"), data.get("password"), data.get("email")
            success = register_user(email, username, password)
            msg_text = f"Welcome to SecureChat, {username}!" if success else "User exists"
        else:
            send(conn, {"type":"error","reason":"AUTH_REQUIRED"}); conn.close(); return

        resp_plain = json.dumps({"type":"auth_response","success":success,"message":msg_text,"server_nonce":s_nonce}).encode()
        resp_ct = aes.encrypt(aes_key, resp_plain)
        canon_resp = canon_bytes(resp_ct, utils.now_ms(), c_nonce, s_nonce)
        resp_mac = aes.hmac_sha256_b64(hmac_key, canon_resp)
        s_priv = sign_mod.load_private_key(SERVER_KEY, None)
        resp_sig = sign_mod.sign(s_priv, canon_resp)
        send(conn, {"type":"secure","ciphertext":resp_ct,"seq":utils.now_ms(),"client_nonce":c_nonce,
                    "server_nonce":s_nonce,"hmac":resp_mac,"signature":resp_sig})
        transcript.append(3, {"event":"auth","user":username,"success":success})
        if not success: conn.close(); return

        # Phase 4: Messaging
        session = ChatSession(conn, username, aes_key, hmac_key, c_nonce, s_nonce, client_pub, s_priv, transcript)
        active_sessions[username] = session
        print(f"[+] User '{username}' connected and ready for chat")

        while session.active:
            try:
                msg = recv(conn, timeout=1)
            except socket.timeout: continue
            except ConnectionError: break

            if msg.get("type")=="quit": break
            if msg.get("type")!="secure": continue

            ct, seq, mac, sig = msg["ciphertext"], msg["seq"], msg["hmac"], msg["signature"]
            if session.last_seq and seq <= session.last_seq: send(conn, {"type":"error","reason":"REPLAY"}); break
            canon = canon_bytes(ct, seq, c_nonce, s_nonce)
            if not aes.verify_hmac_sha256_b64(hmac_key, canon, mac) or not sign_mod.verify(client_pub, canon, sig):
                send(conn, {"type":"error","reason":"SEC_FAIL"}); break

            pt = json.loads(aes.decrypt(aes_key, ct).decode())
            session.last_seq = seq
            print(f"\r{username}> {pt.get('text')}\nServer> ", end="", flush=True)

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()
        session.active=False
        active_sessions.pop(username, None)
        print(f"\n[-] {username if 'username' in locals() else addr} disconnected")

def server_input():
    while True:
        try:
            msg = input("Server> ").strip()
            if not msg: continue
            if msg.startswith('@'):
                target, text = msg[1:].split(' ',1)
                if target in active_sessions: active_sessions[target].send_encrypted(text)
            else:
                for s in active_sessions.values(): s.send_encrypted(msg)
        except Exception: continue

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[*] SecureChat Server listening on {HOST}:{PORT}")
    threading.Thread(target=server_input, daemon=True).start()
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down")
    finally:
        s.close()

if __name__=="__main__":
    main()
