from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime

# -------------------------------
# Certificate helpers
# -------------------------------
def load_certificate(pem_path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.
    """
    with open(pem_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def validate_certificate(cert_pem: str, ca_cert_path: str, expected_cn: str):
    """
    Validate a certificate against a root CA and check the Common Name (CN).
    
    Parameters:
        cert_pem (str): PEM-encoded certificate to validate.
        ca_cert_path (str): Path to root CA certificate (PEM).
        expected_cn (str): Expected Common Name (CN) of certificate.
    
    Returns:
        tuple: (is_valid: bool, reason: str)
    """
    try:
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Load the root CA certificate
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Verify the certificate signature using the CA's public key
        ca_cert.public_key().verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=asym_padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm
        )

        # Check validity period
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (cert.not_valid_before <= now <= cert.not_valid_after):
            return False, "Certificate expired or not yet valid"

        # Check Common Name
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attr[0].value if cn_attr else None
        if cn != expected_cn:
            return False, f"Expected CN={expected_cn}, got {cn}"

        return True, "OK"

    except Exception as e:
        return False, f"Validation failed: {e}"


# -------------------------------
# Quick test
# -------------------------------
if __name__ == "__main__":
    cert_path = "certs/client_cert.pem"
    ca_path = "certs/root_ca_cert.pem"
    expected_cn = "client.local"

    cert = load_certificate(cert_path)
    print("Loaded certificate:", cert.subject)

    valid, reason = validate_certificate(cert.public_bytes(encoding=x509.Encoding.PEM).decode(), ca_path, expected_cn)
    print("Validation result:", valid, "-", reason)
