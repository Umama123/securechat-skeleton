import os, json, socket, struct, hashlib, threading
from pathlib import Path
from app.crypto import dh, aes, sign as sign_mod, pki
from app.common import utils
from app.storage.transcript import Transcript, now_ms
from cryptography import x509
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 5001
CLIENT_CERT = "certs/client_cert.pem"
CLIENT_KEY = "certs/client_key.pem"
ROOT_CA = "certs/root_ca_cert.pem"

MODP_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
             "29024E088A67CC74020BBEA63B139B22514A08798E3404DDE" +
             "F9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E4" +
             "85B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE3" +
             "86BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC200" +
             "7CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655" +
             "D23DCA3AD961C62F356208552BB9ED529077096966D670C354" +
             "E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
MODP_G = 2

active = True

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

def derive_hmac(Ks):
    return hashlib.sha256(Ks.to_bytes((Ks.bit_length()+7)//8,'big') + b"auth").digest()

def canon_bytes(cipher, seq, client_nonce, server_nonce):
    return "|".join([cipher or "", str(seq), client_nonce or "", server_nonce or ""]).encode()

def receiver(sock, server_pub, aes_key, hmac_key, c_nonce, s_nonce, user):
    global active
    while active:
        try:
            msg = recv(sock, timeout=1)
            if msg.get("type")=="session_receipt": 
                print("[*] Session ended by server"); active=False; break
            if msg.get("type")=="error": print(f"[!] Server error: {msg.get('reason')}"); active=False; break
            if msg.get("type")!="secure": continue

            canon = canon_bytes(msg.get("ciphertext"), msg.get("seq"), msg.get("client_nonce"), msg.get("server_nonce"))
            if not aes.verify_hmac_sha256_b64(hmac_key, canon, msg.get("hmac")):
                print("[!] HMAC failed"); continue
            if not sign_mod.verify(server_pub, canon, msg.get("signature")):
                print("[!] Signature failed"); continue

            plain = aes.decrypt(aes_key, msg.get("ciphertext"))
            data = json.loads(plain.decode())
            print(f"\rServer> {data.get('text')}\n{user}> ", end="", flush=True)
        except socket.timeout: continue
        except ConnectionError: print("[*] Connection closed"); active=False; break
        except Exception as e: print(f"[!] Receive error: {e}"); break

def main():
    global active
    print("SecureChat Client\n")
    choice = input("[1] Login\n[2] Register\nChoose: ").strip()
    if choice not in ['1','2']: return
    register = (choice=='2')

    email = input("Email: ").strip() if register else None
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    if register:
        confirm = input("Confirm: ").strip()
        if password != confirm or len(password)<6: print("[!] Invalid"); return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    session_id = f"client_{now_ms()}"
    transcript = Transcript(session_id=session_id)

    # Phase 1: Cert exchange
    client_cert = Path(CLIENT_CERT).read_text()
    c_nonce = utils.b64e(os.urandom(16))
    send(sock, {"type":"client_hello","client cert":client_cert,"nonce":c_nonce})
    transcript.append(0, {"event":"client_hello"})
    srv_hello = recv(sock)
    s_nonce = srv_hello.get("nonce")
    server_cert = srv_hello.get("server cert")
    ok, reason = pki.validate_cert(server_cert, ROOT_CA, "server.local")
    if not ok: print("[!] Cert fail:", reason); return
    server_pub = x509.load_pem_x509_certificate(server_cert.encode(), default_backend()).public_key()

    # Phase 2: Diffie-Hellman
    a = dh.generate_private_key(MODP_P)
    A = dh.generate_public_key(MODP_G, a, MODP_P)
    send(sock, {"type":"dh_client","g":MODP_G,"p":str(MODP_P),"A":str(A)})
    B = int(recv(sock).get("B"))
    transcript.append(1, {"event":"dh","client_A":A,"server_B":B})

    Ks = dh.compute_shared_secret(B, a, MODP_P)
    aes_key = dh.derive_aes_key(Ks)
    hmac_key = derive_hmac(Ks)

    # Phase 3: Auth
    seq = now_ms()
    auth = {"type":"register_request" if register else "login_request","username":username,"password":password}
    if register: auth["email"]=email
    ct = aes.encrypt(aes_key, json.dumps(auth).encode())
    canon = canon_bytes(ct, seq, c_nonce, s_nonce)
    mac = aes.hmac_sha256_b64(hmac_key, canon)
    sig = sign_mod.sign(sign_mod.load_private_key(CLIENT_KEY), canon)
    send(sock, {"type":"secure","ciphertext":ct,"seq":seq,"client_nonce":c_nonce,"server_nonce":s_nonce,"hmac":mac,"signature":sig})
    transcript.append(2, {"event":"auth","user":username})

    resp = recv(sock)
    canon = canon_bytes(resp.get("ciphertext"), resp.get("seq"), resp.get("client_nonce"), resp.get("server_nonce"))
    if not aes.verify_hmac_sha256_b64(hmac_key, canon, resp.get("hmac")) or not sign_mod.verify(server_pub, canon, resp.get("signature")):
        print("[!] Auth verification failed"); return
    data = json.loads(aes.decrypt(aes_key, resp.get("ciphertext")).decode())
    if not data.get("success"): print(f"[!] {data.get('message')}"); return
    print(f"[+] {data.get('message')}")

    # Phase 4: Chat
    t = threading.Thread(target=receiver, args=(sock, server_pub, aes_key, hmac_key, c_nonce, s_nonce, username), daemon=True)
    t.start()
    while active:
        msg = input(f"{username}> ").strip()
        if msg.lower()=='quit': active=False; send(sock, {"type":"quit"}); break
        seq = now_ms()
        ct = aes.encrypt(aes_key, json.dumps({"type":"app_msg","seq":seq,"ts":now_ms(),"text":msg}).encode())
        canon = canon_bytes(ct, seq, c_nonce, s_nonce)
        mac = aes.hmac_sha256_b64(hmac_key, canon)
        sig = sign_mod.sign(sign_mod.load_private_key(CLIENT_KEY), canon)
        send(sock, {"type":"secure","ciphertext":ct,"seq":seq,"client_nonce":c_nonce,"server_nonce":s_nonce,"hmac":mac,"signature":sig})

    t.join(timeout=2)
    sock.close()
    print("[*] Connection closed")

if __name__=="__main__":
    main()
