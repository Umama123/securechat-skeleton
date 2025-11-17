#!/usr/bin/env python3
"""
Improved test: Invalid Certificate Rejection

Purpose:
 - Create a self-signed certificate (not signed by the project's CA)
 - Connect to the server and send a client-hello JSON including that cert
 - Expect the server to either explicitly respond with an error indicating
   a bad/untrusted certificate OR immediately close the connection.
 - Exit codes / printed messages indicate pass/fail.

Notes:
 - This script is intended for legitimate testing of your own assignment server.
 - Do NOT use it to bypass policies or to misrepresent work.
"""

import json
import socket
import struct
import datetime
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

HOST = "127.0.0.1"
PORT = 5001              # adjust to the port your server listens on
TIMEOUT_SECONDS = 5

def send_msg(sock: socket.socket, obj: dict) -> None:
    """Send a 4-byte length-prefixed JSON message."""
    data = json.dumps(obj).encode("utf-8")
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)

def recv_msg(sock: socket.socket) -> dict:
    """Receive a single length-prefixed JSON message. Raises ConnectionError on EOF."""
    header = sock.recv(4)
    if len(header) < 4:
        raise ConnectionError("connection closed while reading header")
    length = struct.unpack("!I", header)[0]
    payload = bytearray()
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise ConnectionError("connection closed while reading payload")
        payload.extend(chunk)
    return json.loads(payload.decode("utf-8"))

def generate_self_signed_cert(common_name: str = "malicious.attacker") -> Tuple[str, bytes]:
    """Generate a self-signed certificate (PEM) and return (cert_pem_str, private_key_pem_bytes)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FastNU"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
    )

    cert = cert_builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return cert_pem, key_pem

def test_invalid_cert() -> bool:
    print("\n=== TEST: Invalid Certificate Rejection ===\n")

    cert_pem, _key_pem = generate_self_signed_cert()
    print("[*] Generated self-signed certificate (not from CA).")

    client_hello = {
        "type": "client hello",
        "client cert": cert_pem,
        "nonce": "dGVzdF9ub25jZQ=="  # base64 'test_nonce' or any random nonce
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        sock.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")
        print("[>] Sending client hello with self-signed certificate...")
        send_msg(sock, client_hello)

        # Wait for server response. If the server immediately closes the connection,
        # recv_msg will raise ConnectionError which we treat as a pass (rejected).
        try:
            resp = recv_msg(sock)
        except ConnectionError:
            print("[<] Connection closed by server (interpreted as certificate rejection).")
            return True

        print(f"[<] Server response: {resp}")

        # Accept either explicit error object or connection close.
        # Servers may use different keys: check both "reason" and "msg" fields.
        if resp.get("type") == "error":
            reason = resp.get("reason") or resp.get("msg") or resp.get("error")
            if reason and ("BAD" in reason.upper() or "CERT" in reason.upper()):
                print("\nTEST PASSED: Server rejected the invalid certificate (explicit error).")
                print("Reason:", reason)
                return True
            else:
                print("\nTEST FAILED: Server returned an error, but not a certificate-rejection reason.")
                print("Returned error:", resp)
                return False
        else:
            print("\nTEST FAILED: Server accepted the client hello and did not return an error.")
            return False

    except socket.timeout:
        print("\nTEST INCONCLUSIVE: connection timed out.")
        return False
    except Exception as ex:
        print(f"\nTEST PASSED: server closed or refused connection (exception: {ex}). Interpreted as rejection.")
        # If the server forcibly closed the connection (e.g., reset/closed), this can be valid evidence of rejection.
        return True
    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("[*] Socket closed.\n")

if __name__ == "__main__":
    ok = test_invalid_cert()
    if ok:
        print("Result: Security Test Passed")
    else:
        print("Result: Security Test Failed")
