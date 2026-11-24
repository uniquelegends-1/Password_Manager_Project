"""Recovery, Versioned Encrypted Backups, SHA-256 Checksums, Ed25519 Signatures & JSON Portability."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shield_core.key_management import (
    CryptoError,
    DecryptionError,
    KdfParams,
    decrypt_aes_gcm,
    derive_kek_argon2id,
    encrypt_aes_gcm,
    generate_salt,
    public_key_fingerprint,
    restrict_file_permissions,
    sign_ed25519,
    verify_ed25519,
)

if TYPE_CHECKING:
    from shield_core.vault_engine import VaultEntry

BACKUP_FORMAT_VERSION = 1
BACKUP_FORMAT_ID = "pulse-shield-encrypted-backup-v1"


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".shield_bak_", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            json.dump(data, tmp_file, indent=2, ensure_ascii=False)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        restrict_file_permissions(tmp_name)
        os.replace(tmp_name, path)
        restrict_file_permissions(path)
    except Exception:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
        raise


def _compute_backup_checksum(header: dict[str, Any], nonce_b64: str, ciphertext_b64: str) -> str:
    canonical = json.dumps(
        {"header": header, "nonce": nonce_b64, "ciphertext": ciphertext_b64},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def create_encrypted_backup(
    entries: list[VaultEntry],
    deleted_ids: dict[str, str],
    vault_id: str,
    passphrase: str,
    dest_path: str | Path,
    kdf_params: KdfParams | None = None,
    *,
    signing_private_key_b64: str = "",
    signing_public_key_b64: str = "",
) -> Path:
    """Export vault records into a checksummed, Ed25519-signed Argon2id + AES-256-GCM backup."""
    if not passphrase:
        raise ValueError("Passphrase is required to encrypt a backup.")

    dest = Path(dest_path)
    params = kdf_params or KdfParams()
    salt = generate_salt()
    key = derive_kek_argon2id(passphrase, salt, params)

    header = {
        "format": BACKUP_FORMAT_ID,
        "version": BACKUP_FORMAT_VERSION,
        "vault_id": vault_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "kdf": params.to_dict(),
        "salt": base64.b64encode(salt).decode("ascii"),
    }
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    payload = {
        "entries": [asdict(e) for e in entries],
        "deleted_ids": dict(deleted_ids),
        "entry_count": len(entries),
    }
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    nonce, ciphertext = encrypt_aes_gcm(key, plaintext, aad=aad)

    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    ct_b64 = base64.b64encode(ciphertext).decode("ascii")
    checksum = _compute_backup_checksum(header, nonce_b64, ct_b64)

    envelope: dict[str, Any] = {
        "header": header,
        "nonce": nonce_b64,
        "ciphertext": ct_b64,
        "sha256": checksum,
    }
    if signing_private_key_b64 and signing_public_key_b64:
        envelope["signer_pub"] = signing_public_key_b64
        envelope["signature"] = sign_ed25519(
            signing_private_key_b64, f"shield-backup-sig-v1|{checksum}".encode("utf-8")
        )

    _atomic_write_json(dest, envelope)
    return dest


def create_versioned_backup(
    entries: list[VaultEntry],
    deleted_ids: dict[str, str],
    vault_id: str,
    passphrase: str,
    backup_dir: str | Path,
    kdf_params: KdfParams | None = None,
    *,
    signing_private_key_b64: str = "",
    signing_public_key_b64: str = "",
) -> Path:
    filename = f"shield_vault_{_utc_stamp()}.shield.enc"
    return create_encrypted_backup(
        entries,
        deleted_ids,
        vault_id,
        passphrase,
        Path(backup_dir) / filename,
        kdf_params=kdf_params,
        signing_private_key_b64=signing_private_key_b64,
        signing_public_key_b64=signing_public_key_b64,
    )


def decrypt_encrypted_backup(
    backup_path: str | Path, passphrase: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Verify checksum + Ed25519 signature + decrypt AES-256-GCM backup.

    Returns (header, payload, integrity_meta).
    """
    path = Path(backup_path)
    if not path.is_file():
        raise FileNotFoundError(f"Backup file not found: {path}")

    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        header = envelope["header"]
        if header.get("format") != BACKUP_FORMAT_ID:
            raise CryptoError("Unrecognized backup format.")
        params = KdfParams.from_dict(header["kdf"])
        salt = base64.b64decode(header["salt"], validate=True)
        nonce_b64 = str(envelope["nonce"])
        ct_b64 = str(envelope["ciphertext"])
        nonce = base64.b64decode(nonce_b64, validate=True)
        ciphertext = base64.b64decode(ct_b64, validate=True)
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("Backup file is corrupted or malformed.") from exc

    # 1. Verify SHA-256 checksum (Integrity)
    recomputed_sha256 = _compute_backup_checksum(header, nonce_b64, ct_b64)
    stored_sha256 = str(envelope.get("sha256", ""))
    if stored_sha256 and stored_sha256 != recomputed_sha256:
        raise CryptoError("Backup integrity check failed: SHA-256 checksum mismatch (file corrupted or modified).")

    # 2. Verify Ed25519 Digital Signature if present (Authenticity & Non-Repudiation)
    signer_pub = str(envelope.get("signer_pub", ""))
    signature = str(envelope.get("signature", ""))
    sig_verified = False
    signer_fp = "UNSIGNED"
    if signer_pub or signature:
        if not signer_pub or not signature:
            raise CryptoError("Backup authenticity failed: incomplete Ed25519 signature.")
        if not verify_ed25519(signer_pub, f"shield-backup-sig-v1|{recomputed_sha256}".encode("utf-8"), signature):
            raise CryptoError("Backup authenticity failed: invalid Ed25519 digital signature.")
        sig_verified = True
        signer_fp = public_key_fingerprint(signer_pub)

    # 3. Decrypt & Authenticate via Argon2id + AES-256-GCM (Confidentiality & Integrity)
    key = derive_kek_argon2id(passphrase, salt, params)
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plaintext = decrypt_aes_gcm(key, nonce, ciphertext, aad=aad)

    try:
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload.get("entries"), list):
            raise ValueError("Missing entries list")
    except Exception as exc:
        raise CryptoError("Decrypted backup payload is malformed.") from exc

    integrity_meta = {
        "sha256": recomputed_sha256,
        "signature_verified": sig_verified,
        "signer_fingerprint": signer_fp,
    }
    return header, payload, integrity_meta


def verify_backup_integrity(backup_path: str | Path, passphrase: str) -> dict[str, Any]:
    """Perform a non-destructive restore test, checksum verification, and signature check."""
    try:
        header, payload, meta = decrypt_encrypted_backup(backup_path, passphrase)
        entries = payload.get("entries", [])
        sig_note = f"Ed25519 Verified ({meta['signer_fingerprint']})" if meta["signature_verified"] else "Unsigned"
        return {
            "valid": True,
            "entry_count": len(entries),
            "created_at": header.get("created_at", ""),
            "vault_id": header.get("vault_id", ""),
            "kdf": header.get("kdf", {}).get("algorithm", "argon2id"),
            "sha256": meta["sha256"],
            "signature_verified": meta["signature_verified"],
            "signer_fingerprint": meta["signer_fingerprint"],
            "message": f"Integrity & authenticity verified: {len(entries)} records • {sig_note}.",
        }
    except (DecryptionError, CryptoError, FileNotFoundError, ValueError) as exc:
        return {
            "valid": False,
            "entry_count": 0,
            "created_at": "",
            "vault_id": "",
            "kdf": "",
            "sha256": "",
            "signature_verified": False,
            "signer_fingerprint": "",
            "message": str(exc),
        }


def export_plaintext_json(entries: list[VaultEntry], dest_path: str | Path) -> Path:
    dest = Path(dest_path)
    data = {
        "format": "pulse-shield-plaintext-json-v1",
        "warning": "UNENCRYPTED SENSITIVE CREDENTIAL EXPORT — DELETE IMMEDIATELY AFTER USE",
        "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "entries": [asdict(e) for e in entries],
    }
    _atomic_write_json(dest, data)
    return dest


def parse_plaintext_json(src_path: str | Path) -> list[dict[str, Any]]:
    path = Path(src_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("entries"), list):
        return [item for item in data["entries"] if isinstance(item, dict)]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    raise ValueError("JSON file does not contain a valid 'entries' list.")
