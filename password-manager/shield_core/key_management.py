"""Key Management Engine: Argon2id KDF, AES-256-GCM, VMK/DEK key wrapping, and Recovery Kit.

Security invariants:
- Master password is NEVER stored.
- Master KEK is derived via Argon2id (memory-hard) and exists only in RAM while unlocked.
- Vault Master Key (VMK) is randomly generated (256-bit) and wrapped under Master KEK.
- Every credential record gets its own independent 256-bit Data Encryption Key (DEK),
  wrapped under VMK with AAD binding record IDs.
- Emergency Recovery Kit optionally wraps VMK under a 256-bit offline Recovery Key
  (zero-reset architecture: no backdoor, no password reset without recovery material).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12

# OWASP recommended interactive Argon2id defaults (64 MiB, 3 iterations, 4 lanes)
DEFAULT_ARGON2_TIME = 3
DEFAULT_ARGON2_MEMORY_KIB = 65536
DEFAULT_ARGON2_LANES = 4

RECOVERY_KEY_PREFIX = "SHIELD-"


class CryptoError(Exception):
    """Base error for key derivation or authenticated decryption failures."""


class DecryptionError(CryptoError):
    """Raised when AES-256-GCM authentication tag verification fails."""


@dataclass(frozen=True)
class KdfParams:
    algorithm: str = "argon2id"
    iterations: int = DEFAULT_ARGON2_TIME
    memory_cost: int = DEFAULT_ARGON2_MEMORY_KIB
    lanes: int = DEFAULT_ARGON2_LANES

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "iterations": self.iterations,
            "memory_cost": self.memory_cost,
            "lanes": self.lanes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KdfParams":
        algo = str(data.get("algorithm", "argon2id")).lower()
        if algo != "argon2id":
            raise CryptoError(f"Unsupported KDF algorithm: {algo}")
        # Clamp lower and upper bounds to prevent DoS/OOM from untrusted backup or E2EE packets
        return cls(
            algorithm=algo,
            iterations=max(1, min(20, int(data.get("iterations", DEFAULT_ARGON2_TIME)))),
            memory_cost=max(8192, min(524288, int(data.get("memory_cost", DEFAULT_ARGON2_MEMORY_KIB)))),
            lanes=max(1, min(16, int(data.get("lanes", DEFAULT_ARGON2_LANES)))),
        )


def generate_random_key(length: int = KEY_LENGTH) -> bytes:
    """Generate a cryptographically secure random key using Python `secrets`."""
    return secrets.token_bytes(length)


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_LENGTH)


def derive_kek_argon2id(secret_text: str, salt: bytes, params: KdfParams | None = None) -> bytes:
    """Derive a 256-bit Key Encryption Key using Argon2id."""
    if not secret_text:
        raise ValueError("Secret passphrase cannot be empty.")
    p = params or KdfParams()
    kdf = Argon2id(
        salt=salt,
        length=KEY_LENGTH,
        iterations=p.iterations,
        lanes=p.lanes,
        memory_cost=p.memory_cost,
    )
    return kdf.derive(secret_text.encode("utf-8"))


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt bytes with AES-256-GCM using a fresh 96-bit random nonce. Returns (nonce, ciphertext)."""
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return nonce, ciphertext


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Authenticate and decrypt AES-256-GCM ciphertext."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad or None)
    except InvalidTag as exc:
        raise DecryptionError("Authentication failed: incorrect key or tampered data.") from exc


def wrap_key(kek: bytes, target_key: bytes, context: str) -> dict[str, str]:
    """Wrap a 256-bit key under a KEK using AES-256-GCM with context AAD."""
    nonce, ct = encrypt_aes_gcm(kek, target_key, aad=context.encode("utf-8"))
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }


def unwrap_key(kek: bytes, wrapped: dict[str, str], context: str) -> bytes:
    """Unwrap a 256-bit key wrapped by `wrap_key`."""
    try:
        nonce = base64.b64decode(wrapped["nonce"], validate=True)
        ct = base64.b64decode(wrapped["ct"], validate=True)
    except Exception as exc:
        raise CryptoError("Malformed wrapped key envelope.") from exc
    return decrypt_aes_gcm(kek, nonce, ct, aad=context.encode("utf-8"))


def encrypt_record_with_per_record_dek(
    vmk: bytes,
    record_id: str,
    payload_dict: dict[str, Any],
    updated_at: str,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Encrypt a single credential record using its own fresh 256-bit DEK.

    Returns (dek_nonce, wrapped_dek, payload_nonce, payload_ciphertext).
    """
    dek = generate_random_key(KEY_LENGTH)
    dek_aad = f"shield-dek-v1:{record_id}".encode("utf-8")
    dek_nonce, wrapped_dek = encrypt_aes_gcm(vmk, dek, aad=dek_aad)

    payload_bytes = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")
    rec_aad = f"shield-rec-v1:{record_id}:{updated_at}".encode("utf-8")
    payload_nonce, payload_ct = encrypt_aes_gcm(dek, payload_bytes, aad=rec_aad)
    return dek_nonce, wrapped_dek, payload_nonce, payload_ct


def decrypt_record_with_per_record_dek(
    vmk: bytes,
    record_id: str,
    dek_nonce: bytes,
    wrapped_dek: bytes,
    payload_nonce: bytes,
    payload_ct: bytes,
    updated_at: str,
) -> dict[str, Any]:
    """Unwrap a record's DEK with VMK and decrypt the record payload."""
    dek_aad = f"shield-dek-v1:{record_id}".encode("utf-8")
    dek = decrypt_aes_gcm(vmk, dek_nonce, wrapped_dek, aad=dek_aad)

    rec_aad = f"shield-rec-v1:{record_id}:{updated_at}".encode("utf-8")
    plaintext = decrypt_aes_gcm(dek, payload_nonce, payload_ct, aad=rec_aad)
    try:
        data = json.loads(plaintext.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Record payload is not a JSON object")
        return data
    except Exception as exc:
        raise CryptoError("Decrypted record payload is malformed.") from exc


def generate_recovery_key() -> str:
    """Generate a high-entropy 200-bit formatted Emergency Recovery Key (SHIELD-XXXX-...)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 unambiguous chars -> 5 bits each
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(8)]
    return RECOVERY_KEY_PREFIX + "-".join(groups)


def normalize_recovery_key(raw: str) -> str:
    """Normalize a user-entered recovery key (case/whitespace/hyphen tolerant)."""
    cleaned = raw.strip().upper()
    if cleaned.startswith(RECOVERY_KEY_PREFIX):
        cleaned = cleaned[len(RECOVERY_KEY_PREFIX) :]
    alnum = "".join(ch for ch in cleaned if ch.isalnum())
    if len(alnum) != 40:
        raise ValueError("Invalid Emergency Recovery Key format (expected 8 groups of 5 characters).")
    groups = [alnum[i : i + 5] for i in range(0, 40, 5)]
    return RECOVERY_KEY_PREFIX + "-".join(groups)


# ------------------------------------------------------------------ #
# Ed25519 Digital Signatures (Authenticity & Non-Repudiation)
# ------------------------------------------------------------------ #


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generate an Ed25519 signing keypair returned as (private_b64, public_b64)."""
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(priv_raw).decode("ascii"), base64.b64encode(pub_raw).decode("ascii")


def sign_ed25519(private_key_b64: str, message: bytes) -> str:
    """Create a 64-byte Ed25519 digital signature encoded in base64."""
    raw = base64.b64decode(private_key_b64.strip(), validate=True)
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return base64.b64encode(priv.sign(message)).decode("ascii")


def verify_ed25519(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 digital signature against a base64 public key."""
    try:
        pub_raw = base64.b64decode(public_key_b64.strip(), validate=True)
        sig_raw = base64.b64decode(signature_b64.strip(), validate=True)
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        pub.verify(sig_raw, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_fingerprint(public_key_b64: str) -> str:
    """Short human-readable fingerprint for an Ed25519 public key (SHIELD-SIG-XXXXXXXXXXXX)."""
    if not public_key_b64:
        return "UNSIGNED"
    digest = hashlib.sha256(public_key_b64.strip().encode("ascii")).hexdigest()[:12].upper()
    return f"SHIELD-SIG-{digest}"


# ------------------------------------------------------------------ #
# Integrity Checksums & Restrictive File Permissions
# ------------------------------------------------------------------ #


def compute_record_digest(
    record_id: str,
    dek_nonce: bytes,
    wrapped_dek: bytes,
    payload_nonce: bytes,
    ciphertext: bytes,
    updated_at: str,
) -> str:
    """Compute a SHA-256 integrity digest covering a full encrypted SQLite credential row."""
    h = hashlib.sha256()
    h.update(b"shield-row-v1|")
    h.update(record_id.encode("utf-8"))
    h.update(b"|")
    h.update(dek_nonce)
    h.update(b"|")
    h.update(wrapped_dek)
    h.update(b"|")
    h.update(payload_nonce)
    h.update(b"|")
    h.update(ciphertext)
    h.update(b"|")
    h.update(updated_at.encode("utf-8"))
    return h.hexdigest()


def restrict_file_permissions(path: str | Path) -> None:
    """Apply owner-only (0o600) permissions where supported by the OS."""
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

