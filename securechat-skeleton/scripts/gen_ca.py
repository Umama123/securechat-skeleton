"""
Generate a Root CA (self-signed) certificate and private key
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Create certs directory if it doesn't exist
CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

# File paths
ROOT_KEY_PATH = os.path.join(CERTS_DIR, "root_ca_key.pem")
ROOT_CERT_PATH = os.path.join(CERTS_DIR, "root_ca_cert.pem")

# Generate RSA private key for Root CA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Save the private key to a PEM file
with open(ROOT_KEY_PATH, "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Define the Root CA subject and issuer (self-signed)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lahore"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"QuantumTech"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"QuantumTech Root CA"),
])

# Build the self-signed Root CA certificate
root_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years validity
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    .sign(private_key, hashes.SHA256())
)

# Save the certificate to a PEM file
with open(ROOT_CERT_PATH, "wb") as f:
    f.write(root_cert.public_bytes(serialization.Encoding.PEM))

print("[+] Root CA generated successfully!")
print(f"Private key: {ROOT_KEY_PATH}")
print(f"Certificate: {ROOT_CERT_PATH}")
