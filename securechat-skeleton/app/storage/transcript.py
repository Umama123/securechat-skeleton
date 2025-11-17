"""
Append-only session transcript with hash chaining and optional RSA signing.

Features:
- Append records with sequence numbers.
- Maintain hash chain: chain_i = SHA256(chain_{i-1} || entry_hash_i)
- Persist transcripts under `transcripts/`.
- Export signed SessionReceipt using RSA private key if provided.
"""

import os
import json
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from app.crypto import sign as sign_mod
except ImportError:
    sign_mod = None

TRANSCRIPT_DIR = Path("transcripts")
TRANSCRIPT_DIR.mkdir(exist_ok=True, parents=True)


def current_millis() -> int:
    """Return current timestamp in milliseconds."""
    return int(time.time() * 1000)


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 hash of `data` as hex string."""
    return hashlib.sha256(data).hexdigest()


class Transcript:
    """
    Manage an append-only transcript for a single session.
    Each record contains:
      { seq, ts, body, entry_hash, chain_hash }
    """
    def __init__(self, session_id: str, fresh_start: bool = True):
        self.session_id = session_id
        self.file_path = TRANSCRIPT_DIR / f"{session_id}.log"
        self._last_chain: Optional[str] = None

        if self.file_path.exists():
            if fresh_start:
                timestamp = int(time.time())
                backup_path = TRANSCRIPT_DIR / f"{session_id}_{timestamp}.log.bak"
                self.file_path.rename(backup_path)
                print(f"[*] Existing transcript backed up to {backup_path.name}")
            else:
                self._load_last_chain()

    def _load_last_chain(self) -> None:
        """Load the last chain hash from the existing transcript file."""
        last_hash = None
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        obj = json.loads(line)
                        last_hash = obj.get("chain_hash")
                    except json.JSONDecodeError:
                        continue
        self._last_chain = last_hash

    def get_last_chain(self) -> Optional[str]:
        """Return the latest chain hash, or None if transcript is empty."""
        return self._last_chain

    def append(self, seq: int, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Append a record to the transcript.
        Returns the record with computed entry_hash and chain_hash.
        """
        # Compute entry hash
        body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash_bytes = sha256_hex(body_bytes).encode("utf-8")

        # Compute chain hash
        prev_chain_bytes = self._last_chain.encode("utf-8") if self._last_chain else b""
        chain_hash = sha256_hex(prev_chain_bytes + entry_hash_bytes)

        # Construct record
        record = {
            "seq": seq,
            "ts": current_millis(),
            "body": body,
            "entry_hash": entry_hash_bytes.decode("utf-8"),
            "chain_hash": chain_hash
        }

        # Append to file
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

        self._last_chain = chain_hash
        return record

    def export_receipt(
        self,
        signer_privkey_path: Optional[str] = None,
        signer_password: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Export a SessionReceipt:
          - session_id
          - final_chain_hash
          - timestamp
          - signature (base64) if signer_privkey_path provided
        """
        final_hash = self.get_last_chain()
        if not final_hash:
            raise ValueError("Transcript is empty; cannot generate receipt.")

        receipt = {
            "session_id": self.session_id,
            "final_chain_hash": final_hash,
            "ts": current_millis(),
        }

        if signer_privkey_path and sign_mod:
            try:
                priv_key = sign_mod.load_private_key(signer_privkey_path, password=signer_password)
                receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
                signature_b64 = sign_mod.sign(priv_key, receipt_bytes)
                receipt["signature"] = signature_b64
            except Exception as e:
                receipt["sign_error"] = str(e)

        return receipt

    def dump(self) -> str:
        """Return entire transcript as a string (for offline verification)."""
        if not self.file_path.exists():
            return ""
        with open(self.file_path, "r", encoding="utf-8") as f:
            return f.read()
