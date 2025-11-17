import base64
import hashlib
import time

# ---------------------------------------------------------
# Utility: current time in milliseconds
# ---------------------------------------------------------
def current_millis() -> int:
    """
    Returns the UNIX timestamp in milliseconds.
    Can be used for message creation times or signature metadata.
    """
    return round(time.time() * 1000)

# ---------------------------------------------------------
# Utility: Base64 encode (bytes → str)
# ---------------------------------------------------------
def encode_base64(raw_bytes: bytes) -> str:
    """
    Encodes a byte sequence into a Base64 string.
    Output is always UTF‑8 text.
    """
    return base64.b64encode(raw_bytes).decode("utf-8")

# ---------------------------------------------------------
# Utility: Base64 decode (str → bytes)
# ---------------------------------------------------------
def decode_base64(b64_text: str) -> bytes:
    """
    Decodes a Base64 string back into the original bytes.
    """
    return base64.b64decode(b64_text.encode("utf-8"))

# ---------------------------------------------------------
# Utility: SHA‑256 hashing (bytes → hex)
# ---------------------------------------------------------
def sha256_digest(data: bytes) -> str:
    """
    Produces a SHA‑256 hash of the provided bytes and
    returns the digest in hexadecimal notation.
    Useful for integrity verification.
    """
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------
# Example ciphertext — Added as requested
# (You can replace it if needed)
# ---------------------------------------------------------
sample_cipher_bytes = b"\x93\xaf\x10\x56\x22\x88\xaa\x44\xfe\x90"
sample_cipher_b64 = encode_base64(sample_cipher_bytes)

print("Sample ciphertext (bytes):", sample_cipher_bytes)
print("Sample ciphertext (Base64):", sample_cipher_b64)
print("SHA‑256 of ciphertext:", sha256_digest(sample_cipher_bytes))
print("Timestamp (ms):", current_millis())
