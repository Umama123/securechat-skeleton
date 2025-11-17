# SecureChat - PKI-Enabled Secure Messaging System
**Assignment #2 - CS-3002 Information Security (Fall 2025)**

A console-based secure chat system implementing **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)** through application-layer cryptography without TLS/SSL.

---

## Features

**X.509 PKI** - Certificate-based mutual authentication  
**Diffie-Hellman** - Secure key exchange (2048-bit MODP)  
**AES-128** - Message encryption with PKCS#7 padding  
**HMAC-SHA256** - Message integrity verification  
**RSA-2048 Signatures** - Authenticity and non-repudiation  
**Hash Chain Transcripts** - Tamper-evident audit logs  
**User Authentication** - MySQL-backed login/registration  
**Bidirectional Chat** - Real-time encrypted messaging  
**Multi-User Support** - Concurrent sessions with threading  

---

## Setup

### Prerequisites
- Python 3.11+
- MySQL 8.0+ (for user authentication)
- Virtual environment
- Wireshark (optional - for traffic analysis)

### Installation

```bash
git clone https://github.com/AnooshaaAli/securechat-skeleton.git
cd securechat-skeleton

python3 -m venv .venv
source .venv/bin/activate 
pip install -r requirements.txt
```

### Database Setup

```bash
brew services start mysql 
mysql -u root -p
```

```sql
CREATE DATABASE securechat;
USE securechat;

CREATE TABLE users (
    email    VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt     BINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    INDEX idx_username (username)
);

EXIT;
```

Or use the provided script:
```bash
python -m app.storage.db --init
```

### Generate Certificates

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client
```

**Generated files:**
- `certs/root_ca_cert.pem` - Root CA certificate
- `certs/root_ca_key.pem` - Root CA private key
- `certs/server_cert.pem` & `certs/server_key.pem` - Server credentials
- `certs/client_cert.pem` & `certs/client_key.pem` - Client credentials

---

## Usage

### 1. Start Server

```bash
python -m app.server
```

**Expected Output:**
```
[*] Server listening on 127.0.0.1:5001
[*] Users must authenticate after certificate validation

[*] Commands:
    /list - Show active users
    @username message - Send message to specific user
    message - Broadcast to all users
```

**Server Commands:**
- `/list` - Show all connected users
- `/help` - Display help message
- `@username message` - Send private message to specific user
- `message` - Broadcast to all connected users

### 2. Start Client (in another terminal)

```bash
python -m app.client
```

**Interactive Flow:**

#### Registration (First Time Users)
```
SecureChat - Encrypted Messaging System

[1] Login
[2] Register

Choose an option (1 or 2): 2

User Registration

Email: alice@nu.edu.pk
Username: alice
Password: ********
Confirm password: ********

[*] Connecting to server 127.0.0.1:5001...
[+] Connected to 127.0.0.1:5001

[*] Phase 1: Certificate Validation
[>] Sent client certificate
[<] Received server certificate
[+] Server certificate validated

[*] Phase 2: Key Exchange (Diffie-Hellman)
[+] Shared secret established
[+] AES and HMAC keys derived
[+] Encrypted channel ready

[*] Phase 3: User Authentication (Encrypted)
[*] Registering user 'alice'...
[>] Sent encrypted credentials (AES-128 + HMAC + RSA)

[+] Welcome to SecureChat, alice!

Secure Chat Session Active

You can now send encrypted messages to the server.
The server can also send you messages at any time.
Type your messages below (or 'quit' to exit):

alice> Hello, this is my first message!
Server> Welcome alice!
alice> How are you?
Server> I'm doing great! How can I help you?
alice> quit
[*] Ending session...
[*] Connection closed
```

#### Login (Existing Users)
```
[1] Login
[2] Register

Choose an option (1 or 2): 1

User Login

Username: alice
Password: ********

[+] Welcome back, alice!

alice> Hi again!
Server> Hello alice!
```

---

## Security Testing

### Test Suite Overview

All security tests are automated and demonstrate resistance to common attacks:

| Test | Property Tested | Expected Result |
|------|----------------|-----------------|
| `test_invalid_cert.py` | PKI/Authenticity | `BAD_CERT` error |
| `test_tampered_signature.py` | Integrity/Authenticity | `SIG_FAIL` error |
| `test_replay_attack.py` | Freshness | `REPLAY` error |
| `test_nonrepudiation.py` | Non-Repudiation | Offline verification |

### Run Individual Tests

```bash
python tests/test_invalid_cert.py
python tests/test_tampered_signature.py
python tests/test_replay_attack.py
python tests/test_nonrepudiation.py
```

---

## Wireshark Analysis

### Capture Network Traffic

1. **Start Wireshark** and select **Loopback: lo0** interface
2. **Apply filter:** `tcp.port == 5001`
3. **Start server:** `python -m app.server`
4. **Start client:** `python -m app.client`
5. **Complete a session** (login + send messages)
6. **Stop capture** and analyze

### Key Observations

**Handshake Phase (Plaintext - Expected):**
- Client/server certificates visible (public data)
- DH public keys (g, p, A, B) visible (public parameters)
- Nonces visible (used for session binding)

**Application Messages (Encrypted - SECURE):**
- All message payloads are **base64-encoded ciphertext**
- Plaintext strings like "Hello Server!" are **NOT visible**
- HMAC tags present (integrity protection)
- RSA signatures present (authenticity)

**Security Verified:**
```
Follow TCP Stream → Shows:
- Encrypted ciphertext: "xynlicW0gp1S5HP4Yxu0X4hHtq..."
- HMAC: "1iHAJIFiDZctxHGOfP/mLVQaBC..."
- Signature: "QiuebtTm+TSzRSiK+L8Mw9Ff..."
- NO plaintext application data visible
```

---

## Security Properties (CIANR)

### Confidentiality
- **Mechanism:** AES-128-ECB encryption with DH-derived keys
- **Key Derivation:** `AES_key = SHA256(Ks || "enc")[:16]`
- **Verification:** Wireshark shows only ciphertext, plaintext NOT visible

### Integrity
- **Mechanism:** HMAC-SHA256 over `ciphertext || seq || client_nonce || server_nonce`
- **Attack Resistance:** Any modification breaks HMAC
- **Verification:** Tampered messages rejected with `SIG_FAIL`

### Authenticity
- **Mechanism:** X.509 certificates (validated against Root CA) + RSA-2048 signatures
- **Attack Resistance:** Only CA-signed certs accepted, signatures unforgeable without private key
- **Verification:** Invalid certificates rejected with `BAD_CERT`

### Non-Repudiation
- **Mechanism:** Hash-chain transcripts + signed session receipts
- **Format:** `C_n = SHA256(C_{n-1} || H_n)` where `H_n = SHA256(message_n)`
- **Verification:** Offline transcript validation succeeds, participants cannot deny involvement

### Replay Protection
- **Mechanism:** Monotonically increasing sequence numbers + nonces
- **Attack Resistance:** Messages with `seq ≤ last_seq` rejected
- **Verification:** Replay attacks rejected with `REPLAY`

---

## Authentication Flow

### Credentials Sent ONLY After Encryption Established

1. **Phase 1:** Mutual certificate validation (plaintext - certs are public)
2. **Phase 2:** Diffie-Hellman key exchange (plaintext - public parameters)
3. **Phase 3:** Derive AES + HMAC keys from shared secret
4. **Phase 4:** User sends login/register (ENCRYPTED with AES + HMAC + RSA)
5. **Phase 5:** Server verifies credentials (constant-time comparison)
6. **Phase 6:** Secure messaging begins

**Database Security:**
- Random salt ≥16 bytes per user (`secrets.token_bytes(16)`)
- Password hashing: `SHA256(salt || password)`
- Constant-time comparison: `hmac.compare_digest()`
- No plaintext passwords stored or transmitted

---

## Important Notes

**Do Not Commit**
- Private keys (`*.key`, `*_key.pem`)
- Certificates (`*.pem`)
- `.env` file with database credentials
- Transcript files (`transcripts/*.log`)

---

## Author

**Name:** Anoosha Ali  
**Roll Number:** 22i-1242  
**Section:** J  
**Email:** i221242@nu.edu.pk  
**Course:** CS-3002 Information Security  
**Institution:** FAST-NUCES, Islamabad  
**Semester:** Fall 2025