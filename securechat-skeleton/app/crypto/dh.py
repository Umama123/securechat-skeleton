from hashlib import sha256

def generate_private_key(p: int) -> int:
    """Generate a private DH key (random in range [2, p-2])."""
    from random import randrange
    return randrange(2, p-1)

def generate_public_key(g: int, private: int, p: int) -> int:
    """Compute public DH value."""
    return pow(g, private, p)

def compute_shared_secret(pub: int, private: int, p: int) -> int:
    """Compute DH shared secret Ks = pub^private mod p."""
    return pow(pub, private, p)

def derive_aes_key(Ks: int) -> bytes:
    """SHA-256 of Ks (big-endian) truncated to 16 bytes for AES-128."""
    ks_bytes = Ks.to_bytes((Ks.bit_length() + 7) // 8, 'big')
    return sha256(ks_bytes).digest()[:16]
