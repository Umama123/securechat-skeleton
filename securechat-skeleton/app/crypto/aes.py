from cryptography.hazmat.primitives import padding, ciphers, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes
import base64

BLOCK_SIZE_BITS = 128  # AES block size in bits (16 bytes)

# -------------------------------
# PKCS7 padding helpers
# -------------------------------
def pkcs7_pad(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding to data to make it multiple of AES block size.
    """
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.
    """
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    return unpadder.update(data) + unpadder.finalize()


# -------------------------------
# AES-ECB encrypt/decrypt
# -------------------------------
def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> str:
    """
    Encrypt plaintext using AES-128-ECB with PKCS#7 padding.
    Returns base64-encoded ciphertext string.
    """
    cipher = ciphers.Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pkcs7_pad(plaintext)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8')


def aes_ecb_decrypt(key: bytes, ciphertext_b64: str) -> bytes:
    """
    Decrypt a base64-encoded AES-128-ECB ciphertext.
    Returns the original plaintext bytes.
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = ciphers.Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)


# -------------------------------
# Base64 helpers
# -------------------------------
def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def from_b64(b64_str: str) -> bytes:
    return base64.b64decode(b64_str.encode('utf-8'))


# -------------------------------
# HMAC-SHA256 helpers
# -------------------------------
def hmac_sha256_b64(key: bytes, data: bytes) -> str:
    """
    Compute HMAC-SHA256 over `data` using `key` and return Base64 string.
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    mac = h.finalize()
    return to_b64(mac)


def verify_hmac_sha256_b64(key: bytes, data: bytes, mac_b64: str) -> bool:
    """
    Verify HMAC-SHA256 for given Base64 MAC.
    Returns True if verification passes, False otherwise.
    """
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(from_b64(mac_b64))
        return True
    except Exception:
        return False


# -------------------------------
# Quick test
# -------------------------------
if __name__ == "__main__":
    key = b'1234567890abcdef'  # 16-byte key
    plaintext = b"Hello world, AES-ECB + HMAC test!"
    
    ct_b64 = aes_ecb_encrypt(key, plaintext)
    print("Ciphertext (Base64):", ct_b64)
    
    pt = aes_ecb_decrypt(key, ct_b64)
    print("Decrypted plaintext:", pt)
    
    mac_b64 = hmac_sha256_b64(key, plaintext)
    print("HMAC (Base64):", mac_b64)
    print("Verification:", verify_hmac_sha256_b64(key, plaintext, mac_b64))
