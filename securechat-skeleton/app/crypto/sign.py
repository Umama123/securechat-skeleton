import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# -------------------------------
# RSA Key helpers
# -------------------------------
def load_private_key(path: str, password: bytes = None) -> rsa.RSAPrivateKey:
    """
    Load an RSA private key from PEM file.
    Args:
        path: Path to the PEM private key file.
        password: Optional password for encrypted keys.
    Returns:
        RSAPrivateKey object.
    """
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())


def load_public_key(path: str) -> rsa.RSAPublicKey:
    """
    Load an RSA public key from PEM file.
    Args:
        path: Path to the PEM public key file.
    Returns:
        RSAPublicKey object.
    """
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


# -------------------------------
# Signing & Verification
# -------------------------------
def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> str:
    """
    Sign a message using RSA-PKCS1v15 + SHA256.
    Returns a base64-encoded signature string.
    """
    signature = private_key.sign(
        data=message,
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature_b64: str) -> bool:
    """
    Verify a base64-encoded signature using RSA-PKCS1v15 + SHA256.
    Returns True if valid, False otherwise.
    """
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


# -------------------------------
# Quick test
# -------------------------------
if __name__ == "__main__":
    priv_path = "certs/client_key.pem"
    pub_path = "certs/client_pub.pem"

    priv_key = load_private_key(priv_path)
    pub_key = load_public_key(pub_path)

    msg = b"Test signing message"
    sig_b64 = sign_message(priv_key, msg)

    print("Signature:", sig_b64)
    valid = verify_signature(pub_key, msg, sig_b64)
    print("Signature valid?", valid)
