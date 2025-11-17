import os
import hashlib
import secrets
import hmac
import mysql.connector
from mysql.connector import MySQLConnection

# -------------------------------
# Database Configuration
# -------------------------------
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", 3306))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASS = os.getenv("MYSQL_PASS", "P@ssw0rd")
MYSQL_DB   = os.getenv("MYSQL_DB", "securechat")


# -------------------------------
# Database Connection Helper
# -------------------------------
def get_connection() -> MySQLConnection:
    """Return a new MySQL connection."""
    return mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASS,
        database=MYSQL_DB,
        charset='utf8mb4',
        use_pure=True
    )


# -------------------------------
# Password Hashing
# -------------------------------
def hash_password(salt: bytes, password: str) -> str:
    """
    Hash the password with a given salt using SHA-256.
    Returns hex digest.
    """
    return hashlib.sha256(salt + password.encode('utf-8')).hexdigest()


# -------------------------------
# User Management
# -------------------------------
def register_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user.
    Returns True if successful, False if username/email already exists.
    """
    conn = get_connection()
    cursor = conn.cursor(buffered=True)
    try:
        # Check for existing user/email
        cursor.execute(
            "SELECT 1 FROM users WHERE username=%s OR email=%s", 
            (username, email)
        )
        if cursor.fetchone():
            return False

        # Generate salt and hash password
        salt = secrets.token_bytes(16)
        pwd_hash = hash_password(salt, password)

        # Insert new user
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        return True
    finally:
        cursor.close()
        conn.close()


def verify_user(username: str, password: str) -> bool:
    """
    Verify a user's password.
    Returns True if password matches, False otherwise.
    """
    conn = get_connection()
    cursor = conn.cursor(buffered=True)
    try:
        cursor.execute(
            "SELECT salt, pwd_hash FROM users WHERE username=%s", 
            (username,)
        )
        row = cursor.fetchone()
        if not row:
            return False

        salt, stored_hash = row
        computed_hash = hash_password(salt, password)

        # Constant-time comparison
        return hmac.compare_digest(stored_hash, computed_hash)
    finally:
        cursor.close()
        conn.close()


# -------------------------------
# Quick Demo
# -------------------------------
if __name__ == "__main__":
    print("Register alice:", register_user("alice@example.com", "alice", "password123"))
    print("Verify correct password:", verify_user("alice", "password123"))
    print("Verify wrong password:", verify_user("alice", "wrongpass"))
