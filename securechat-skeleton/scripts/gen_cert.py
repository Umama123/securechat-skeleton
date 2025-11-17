#!/usr/bin/env python3
"""
Generate a signed certificate from the Root CA.

Usage:
    python3 generate_cert.py --cn server.local --out certs/server
    python3 generate_cert.py --cn client.local --out certs/client
"""

import os
import argparse
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName

# -------------------------
# Parse command-line args
# -------------------------
parser = argparse.ArgumentParser(description="Generate a signed certificate from Root CA")
parser.add_argument("--cn", required=True, help="Common Name (CN) for the certificate, e.g., server.local or client.local")
parser.add_argument("--out", required=True, help="Output base path for key & cert (e.g., certs/server)")
args = parser.parse_args()

CN = args.cn
OUT_BASE = args.out
os.makedirs(os.path.dirname(OUT_BASE), exist_ok=True)

# -------------------------
# Load Root CA key & cert
# -------------------------
with open("certs/root_ca_key.pem", "rb") as f:
    ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

with open("certs/root_ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# -------------------------
# Generate entity (server/client) key
# -------------------------
entity_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# -------------------------
# Save private key to PEM
# -------------------------
key_path = f"{OUT_BASE}_key.pem"
with open(key_path, "wb") as f:
    f.write(entity_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# -------------------------
# Build certificate
# -------------------------
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"QuantumTech"),
    x509.NameAttribute(NameOID.COMMON_NAME, CN),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)  # Signed by Root CA
    .public_key(entity_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
    .add_extension(
        x509.SubjectAlternativeName([DNSName(CN)]),
        critical=False
    )
    .sign(ca_private_key, hashes.SHA256())
)

# -------------------------
# Save certificate to PEM
# -------------------------
cert_path = f"{OUT_BASE}_cert.pem"
with open(cert_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# -------------------------
# Success message
# -------------------------
print(f"[+] Certificate for '{CN}' generated successfully!")
print(f"Private key: {key_path}")
print(f"Certificate: {cert_path}")
