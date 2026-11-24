"""P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T. — Central SQLite + Per-Record DEK Vault Engine.

Architecture:
- Storage: SQLite database (`shield_vault.db`) in WAL mode.
- Key Derivation: Argon2id (memory-hard, never stores master password).
- Encryption: AES-256-GCM with a Vault Master Key (VMK) in RAM only while unlocked,
  and an independent random 256-bit Data Encryption Key (DEK) per credential record.
- Zero-Reset Recovery: Optional pre-generated 200-bit Emergency Recovery Key wraps VMK.
- IAM: Progressive brute-force rate limiting + trusted device registry & revocation.
- MFA: RFC 6238 TOTP with anti-replay time-step protection + one-time recovery codes.
- Audit: Hash-chained tamper-evident SQLite security event log with strict secret redaction.
"""

from __future__ import annotations

import base64
import json
import secrets
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shield_core.adaptive_security import AdaptivePolicyConfig, SecurityRequirement, evaluate_action
from shield_core.audit_log import AuditEvent, AuditLog
from shield_core.e2ee import (
    SHARE_PK_PREFIX,
    SHARE_PW_PREFIX,
    decrypt_entry_with_passphrase,
    decrypt_entry_with_private_key,
    encrypt_entry_for_public_key,
    encrypt_entry_with_passphrase,
    generate_x25519_keypair,
)
from shield_core.google_sync import GoogleCsvItem
from shield_core.governance_ops import (
    IncidentCase,
    PatchCheckItem,
    PolicyCheckResult,
    RiskRecord,
    SecurityPolicyConfig,
    check_patch_posture,
    evaluate_policy_compliance,
    render_governance_report_markdown,
    synthesize_auto_risks,
)
from shield_core.identity_access import (
    DeviceRevokedError,
    IdentityAccessManager,
    RateLimitError,
    TrustedDevice,
)
from shield_core.key_management import (
    CryptoError,
    DecryptionError,
    KdfParams,
    compute_record_digest,
    decrypt_aes_gcm,
    decrypt_record_with_per_record_dek,
    derive_kek_argon2id,
    encrypt_aes_gcm,
    encrypt_record_with_per_record_dek,
    generate_ed25519_keypair,
    generate_random_key,
    generate_recovery_key,
    generate_salt,
    normalize_recovery_key,
    public_key_fingerprint,
    restrict_file_permissions,
    unwrap_key,
    wrap_key,
)
from shield_core.mfa import (
    TOTPReplayError,
    generate_recovery_codes,
    hash_recovery_code,
    normalize_totp_secret,
    verify_totp,
    verify_totp_with_step,
)
from shield_core.recovery_backup import (
    create_encrypted_backup,
    create_versioned_backup,
    decrypt_encrypted_backup,
    export_plaintext_json,
    parse_plaintext_json,
    verify_backup_integrity,
)
from shield_core.security_audit import check_password_reuse

SCHEMA_VERSION = 1

ENTRY_TYPES = (
    "Website",
    "Application",
    "Email",
    "Secure Note",
    "Recovery Codes",
    "API Key / Token",
    "Wi-Fi",
    "Software Licence",
)

CATEGORIES = (
    "General",
    "Email",
    "Social",
    "Finance",
    "Work",
    "Developer",
    "Infrastructure",
    "Personal",
    "Other",
)


class VaultError(Exception):
    """Base exception for S.H.I.E.L.D. vault operations."""


class InvalidPasswordError(VaultError):
    """Raised when master password or recovery key fails authentication."""


class VaultFormatError(VaultError):
    """Raised when the vault database is missing required metadata or corrupted."""


class VaultLockedError(VaultError):
    """Raised when attempting to access or modify a locked vault."""


class InvalidMFACodeError(VaultError):
    """Raised when MFA TOTP or recovery code verification fails."""


class VaultIntegrityError(VaultError):
    """Raised when record-set manifest, SQLite integrity, or checksum detects tampering/rollback."""


@dataclass
class VaultEntry:
    id: str
    title: str
    entry_type: str = "Website"
    category: str = "General"
    tags: list[str] = field(default_factory=list)
    favorite: bool = False
    username: str = ""
    password: str = ""
    url: str = ""
    totp_secret: str = ""
    passkey_enabled: bool = False
    custom_fields: dict[str, str] = field(default_factory=dict)
    notes: str = ""
    site_policy: str = ""
    created_at: str = ""
    updated_at: str = ""
    password_updated_at: str = ""
    last_accessed_at: str = ""

    @classmethod
    def create(
        cls,
        title: str,
        *,
        entry_type: str = "Website",
        category: str = "General",
        tags: list[str] | None = None,
        favorite: bool = False,
        username: str = "",
        password: str = "",
        url: str = "",
        totp_secret: str = "",
        passkey_enabled: bool = False,
        custom_fields: dict[str, str] | None = None,
        notes: str = "",
        site_policy: str = "",
    ) -> "VaultEntry":
        now = _utc_now()
        clean_totp = normalize_totp_secret(totp_secret) if totp_secret.strip() else ""
        clean_tags = _normalize_tags(tags or [])
        clean_custom = {str(k).strip(): str(v) for k, v in (custom_fields or {}).items() if str(k).strip()}
        return cls(
            id=str(uuid.uuid4()),
            title=title.strip(),
            entry_type=entry_type if entry_type in ENTRY_TYPES else "Website",
            category=category if category in CATEGORIES else "General",
            tags=clean_tags,
            favorite=bool(favorite),
            username=username.strip(),
            password=password,
            url=url.strip(),
            totp_secret=clean_totp,
            passkey_enabled=bool(passkey_enabled),
            custom_fields=clean_custom,
            notes=notes,
            site_policy=site_policy.strip(),
            created_at=now,
            updated_at=now,
            password_updated_at=now,
            last_accessed_at="",
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultEntry":
        created = str(data.get("created_at", "")) or _utc_now()
        updated = str(data.get("updated_at", "")) or created
        pwd_updated = str(data.get("password_updated_at", "")) or updated
        raw_totp = str(data.get("totp_secret", "")).strip()
        clean_totp = ""
        if raw_totp:
            try:
                clean_totp = normalize_totp_secret(raw_totp)
            except ValueError:
                clean_totp = ""
        raw_tags = data.get("tags", [])
        tags = _normalize_tags(raw_tags if isinstance(raw_tags, list) else [])
        raw_cf = data.get("custom_fields", {})
        cf = (
            {str(k).strip(): str(v) for k, v in raw_cf.items() if str(k).strip()}
            if isinstance(raw_cf, dict)
            else {}
        )
        return cls(
            id=str(data.get("id") or uuid.uuid4()),
            title=str(data.get("title", "")).strip() or "Untitled",
            entry_type=str(data.get("entry_type", "Website"))
            if data.get("entry_type") in ENTRY_TYPES
            else "Website",
            category=str(data.get("category", "General"))
            if data.get("category") in CATEGORIES
            else "General",
            tags=tags,
            favorite=bool(data.get("favorite", False)),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            url=str(data.get("url", "")),
            totp_secret=clean_totp,
            passkey_enabled=bool(data.get("passkey_enabled", False)),
            custom_fields=cf,
            notes=str(data.get("notes", "")),
            site_policy=str(data.get("site_policy", "")),
            created_at=created,
            updated_at=updated,
            password_updated_at=pwd_updated,
            last_accessed_at=str(data.get("last_accessed_at", "")),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _normalize_tags(tags: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for t in tags:
        clean = str(t).strip().lower()
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


class ShieldVault:
    """Zero-trust, local-first SQLite password vault with per-record AES-256-GCM DEKs."""

    def __init__(self, path: str | Path, kdf_params: KdfParams | None = None) -> None:
        self.path = Path(path)
        self._default_kdf = kdf_params or KdfParams()
        self._conn: sqlite3.Connection | None = None
        self._audit: AuditLog | None = None
        self._iam: IdentityAccessManager | None = None

        # Memory-only state while unlocked
        self._vmk: bytes | None = None
        self._vault_id: str = ""
        self._entries: dict[str, VaultEntry] = {}
        self._secrets_blob: dict[str, Any] = {}
        self._adaptive_config = AdaptivePolicyConfig()
        self._security_policy = SecurityPolicyConfig()
        self._mfa_verified: bool = False

        # Pending MFA challenge state (VMK unwrapped, access still blocked until TOTP/recovery passes)
        self._pending_vmk: bytes | None = None
        self._pending_secrets: dict[str, Any] | None = None
        self.last_e2ee_sender_fingerprint: str = ""

    # ------------------------------------------------------------------ #
    # Connection & Schema Management
    # ------------------------------------------------------------------ #

    def _open_db(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_secrets (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                dek_nonce BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL,
                payload_nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
        restrict_file_permissions(self.path)
        self._conn = conn
        self._audit = AuditLog(conn)
        self._iam = IdentityAccessManager(conn)
        return conn

    def close(self) -> None:
        self.lock()
        if self._conn is not None:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            self._conn.close()
            self._conn = None
            self._audit = None
            self._iam = None

    def _get_meta(self, key: str) -> str | None:
        conn = self._open_db()
        row = conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else None

    def _set_meta(self, key: str, value: str) -> None:
        conn = self._open_db()
        conn.execute(
            "INSERT INTO vault_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def exists(self) -> bool:
        if not self.path.is_file():
            return False
        try:
            return self._get_meta("vault_id") is not None
        except Exception:
            return False

    @property
    def is_unlocked(self) -> bool:
        return self._vmk is not None and self._mfa_verified

    @property
    def is_mfa_pending(self) -> bool:
        return self._pending_vmk is not None and not self.is_unlocked

    @property
    def has_recovery_kit(self) -> bool:
        if not self.exists:
            return False
        return self._get_meta("recovery_vmk_wrapped") is not None

    @property
    def vault_id(self) -> str:
        self._require_unlocked()
        return self._vault_id

    @property
    def mfa_enabled(self) -> bool:
        self._require_unlocked()
        return bool(self._secrets_blob.get("mfa", {}).get("enabled", False))

    @property
    def remaining_mfa_recovery_codes(self) -> int:
        self._require_unlocked()
        return len(self._secrets_blob.get("mfa", {}).get("recovery_hashes", []))

    @property
    def public_key(self) -> str:
        self._require_unlocked()
        return str(self._secrets_blob.get("e2ee_public_key", ""))

    @property
    def signing_fingerprint(self) -> str:
        self._require_unlocked()
        return public_key_fingerprint(str(self._secrets_blob.get("signing_public_key", "")))

    @property
    def sync_path(self) -> str:
        self._require_unlocked()
        return str(self._secrets_blob.get("sync_path", ""))

    @property
    def adaptive_config(self) -> AdaptivePolicyConfig:
        self._require_unlocked()
        return self._adaptive_config

    @property
    def security_policy(self) -> SecurityPolicyConfig:
        self._require_unlocked()
        return self._security_policy

    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise VaultLockedError("Vault is locked.")

    def _log(self, event_type: str, summary: str, severity: str = "info", metadata: dict[str, Any] | None = None) -> None:
        if self._audit is not None and self._iam is not None:
            sig_priv = str(self._secrets_blob.get("signing_private_key", "")) if self._vmk is not None else ""
            sig_pub = str(self._secrets_blob.get("signing_public_key", "")) if self._vmk is not None else ""
            self._audit.record(
                event_type,
                summary,
                severity=severity,
                device_id=self._iam.current_device_id,
                metadata=metadata,
                signing_private_key_b64=sig_priv,
                signing_public_key_b64=sig_pub,
                vault_id=self._vault_id or (self._get_meta("vault_id") or ""),
            )

    def _save_secrets_blob(self) -> None:
        assert self._vmk is not None
        conn = self._open_db()
        now = _utc_now()
        plaintext = json.dumps(self._secrets_blob, ensure_ascii=False).encode("utf-8")
        nonce, ct = encrypt_aes_gcm(self._vmk, plaintext, aad=b"shield-vault-secrets-v1")
        conn.execute(
            """
            INSERT INTO vault_secrets (id, nonce, ciphertext, updated_at)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext, updated_at = excluded.updated_at
            """,
            (nonce, ct, now),
        )
        conn.commit()

    def _load_secrets_blob(self, vmk: bytes) -> dict[str, Any]:
        conn = self._open_db()
        row = conn.execute("SELECT nonce, ciphertext FROM vault_secrets WHERE id = 1").fetchone()
        if not row:
            raise VaultFormatError("Missing encrypted vault secrets record.")
        plaintext = decrypt_aes_gcm(vmk, bytes(row[0]), bytes(row[1]), aad=b"shield-vault-secrets-v1")
        data = json.loads(plaintext.decode("utf-8"))
        if not isinstance(data, dict):
            raise VaultFormatError("Corrupted vault secrets payload.")
        return data

    def _load_all_entries(self, vmk: bytes, expected_digests: dict[str, str] | None = None) -> dict[str, VaultEntry]:
        conn = self._open_db()
        rows = conn.execute(
            "SELECT id, dek_nonce, wrapped_dek, payload_nonce, ciphertext, updated_at FROM credentials"
        ).fetchall()
        loaded: dict[str, VaultEntry] = {}
        actual_digests: dict[str, str] = {}
        for rid, dek_nonce, wrapped_dek, p_nonce, ct, updated_at in rows:
            rid_s = str(rid)
            upd_s = str(updated_at)
            dn, wd, pn, cb = bytes(dek_nonce), bytes(wrapped_dek), bytes(p_nonce), bytes(ct)
            actual_digests[rid_s] = compute_record_digest(rid_s, dn, wd, pn, cb, upd_s)
            rec_dict = decrypt_record_with_per_record_dek(vmk, rid_s, dn, wd, pn, cb, upd_s)
            entry = VaultEntry.from_dict(rec_dict)
            entry.id = rid_s
            loaded[entry.id] = entry

        # Anti-deletion / anti-insertion / anti-rollback integrity manifest verification
        if expected_digests is not None:
            missing = set(expected_digests.keys()) - set(actual_digests.keys())
            unexpected = set(actual_digests.keys()) - set(expected_digests.keys())
            mismatched = [
                k for k in (set(expected_digests.keys()) & set(actual_digests.keys()))
                if expected_digests[k] != actual_digests[k]
            ]
            if missing or unexpected or mismatched:
                raise VaultIntegrityError(
                    f"Database integrity violation detected: {len(missing)} deleted, "
                    f"{len(unexpected)} injected, {len(mismatched)} rolled-back/modified record(s)."
                )
        return loaded

    def _persist_entry(self, entry: VaultEntry, *, save_manifest: bool = True) -> None:
        assert self._vmk is not None
        conn = self._open_db()
        dek_nonce, wrapped_dek, payload_nonce, ct = encrypt_record_with_per_record_dek(
            self._vmk, entry.id, asdict(entry), entry.updated_at
        )
        conn.execute(
            """
            INSERT INTO credentials (id, dek_nonce, wrapped_dek, payload_nonce, ciphertext, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                dek_nonce = excluded.dek_nonce,
                wrapped_dek = excluded.wrapped_dek,
                payload_nonce = excluded.payload_nonce,
                ciphertext = excluded.ciphertext,
                updated_at = excluded.updated_at
            """,
            (entry.id, dek_nonce, wrapped_dek, payload_nonce, ct, entry.created_at, entry.updated_at),
        )
        conn.commit()
        digests = self._secrets_blob.setdefault("record_digests", {})
        digests[entry.id] = compute_record_digest(
            entry.id, dek_nonce, wrapped_dek, payload_nonce, ct, entry.updated_at
        )
        if save_manifest:
            self._save_secrets_blob()

    # ------------------------------------------------------------------ #
    # Creation, Authentication, Rate Limiting, MFA & Recovery
    # ------------------------------------------------------------------ #

    def create(self, master_password: str, create_recovery_kit: bool = False) -> str | None:
        """Initialize a new zero-trust SQLite vault with Argon2id + AES-256-GCM.

        Optionally returns a one-time Emergency Recovery Key if `create_recovery_kit=True`.
        """
        if len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters long.")
        self.close()
        if self.path.exists():
            self.path.unlink()
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists():
                sidecar.unlink()

        self._open_db()
        assert self._iam is not None

        vault_id = str(uuid.uuid4())
        vmk = generate_random_key()
        salt = generate_salt()
        kek = derive_kek_argon2id(master_password, salt, self._default_kdf)
        wrapped_vmk = wrap_key(kek, vmk, context="shield-vmk-master-v1")

        self._set_meta("schema_version", str(SCHEMA_VERSION))
        self._set_meta("vault_id", vault_id)
        self._set_meta("created_at", _utc_now())
        self._set_meta("kdf_params", json.dumps(self._default_kdf.to_dict()))
        self._set_meta("master_salt", base64.b64encode(salt).decode("ascii"))
        self._set_meta("master_vmk_wrapped", json.dumps(wrapped_vmk))

        priv_key, pub_key = generate_x25519_keypair()
        sig_priv, sig_pub = generate_ed25519_keypair()
        self._set_meta("signing_public_key", sig_pub)
        self._vmk = vmk
        self._vault_id = vault_id
        self._entries = {}
        self._adaptive_config = AdaptivePolicyConfig()
        self._security_policy = SecurityPolicyConfig()
        self._secrets_blob = {
            "e2ee_private_key": priv_key,
            "e2ee_public_key": pub_key,
            "signing_private_key": sig_priv,
            "signing_public_key": sig_pub,
            "sync_path": "",
            "last_backup_at": "",
            "deleted_ids": {},
            "record_digests": {},
            "adaptive_config": self._adaptive_config.to_dict(),
            "security_policy": self._security_policy.to_dict(),
            "risk_register": [],
            "incidents": [],
            "last_dr_drill": None,
            "mfa": {
                "enabled": False,
                "totp_secret": "",
                "last_used_step": -1,
                "recovery_hashes": [],
            },
        }
        self._mfa_verified = True
        self._save_secrets_blob()

        dev, _ = self._iam.check_or_register_current_device()
        self._log("vault_created", f"Zero-trust SQLite vault initialized on device ({dev.device_id}).", "info")

        if create_recovery_kit:
            return self.generate_emergency_recovery_kit()
        return None

    def _unwrap_vmk_with_master_password(self, master_password: str) -> bytes:
        kdf_raw = self._get_meta("kdf_params")
        salt_raw = self._get_meta("master_salt")
        wrapped_raw = self._get_meta("master_vmk_wrapped")
        if not kdf_raw or not salt_raw or not wrapped_raw:
            raise VaultFormatError("Vault metadata is incomplete or corrupted.")
        params = KdfParams.from_dict(json.loads(kdf_raw))
        salt = base64.b64decode(salt_raw, validate=True)
        wrapped = json.loads(wrapped_raw)
        kek = derive_kek_argon2id(master_password, salt, params)
        return unwrap_key(kek, wrapped, context="shield-vmk-master-v1")

    def unlock(self, master_password: str) -> bool:
        """Authenticate master password with brute-force rate limiting & device trust check.

        Returns True if fully unlocked, or False if Stage-2 MFA verification is required.
        """
        self.lock()
        if not self.exists:
            raise VaultFormatError(f"Vault database not found: {self.path}")

        self._open_db()
        assert self._iam is not None

        # 1. Check brute-force rate limit first
        try:
            self._iam.check_rate_limit("master")
        except RateLimitError as exc:
            self._log("rate_limit_blocked", str(exc), severity="alert")
            raise

        # 2. Reject revoked devices immediately (do NOT auto-register new devices before password succeeds)
        try:
            self._iam.ensure_device_not_revoked()
        except DeviceRevokedError as exc:
            self._log("revoked_device_blocked", str(exc), severity="critical")
            raise

        # 3. Verify master password by unwrapping VMK
        if not master_password:
            fails, lock_secs = self._iam.record_failure("master")
            self._log("unlock_failed", f"Empty master password attempt (#{fails}).", severity="warning")
            raise InvalidPasswordError("Incorrect master password.")

        try:
            vmk = self._unwrap_vmk_with_master_password(master_password)
            secrets_blob = self._load_secrets_blob(vmk)
        except (DecryptionError, CryptoError):
            fails, lock_secs = self._iam.record_failure("master")
            sev = "alert" if fails >= 3 else "warning"
            extra = f" Rate-limited for {lock_secs}s." if lock_secs else ""
            self._log("unlock_failed", f"Failed master password attempt #{fails}.{extra}", severity=sev)
            if lock_secs:
                raise RateLimitError(
                    f"Incorrect master password. Locked out for {lock_secs}s after {fails} failed attempts.",
                    retry_after_seconds=lock_secs,
                )
            raise InvalidPasswordError("Incorrect master password.")

        self._iam.record_success("master")
        dev, is_new_dev = self._iam.check_or_register_current_device()
        if is_new_dev:
            self._log(
                "device_registered",
                f"New device ({dev.device_id}) authenticated and registered.",
                severity="warning",
            )

        # 4. Check if MFA is enabled
        mfa_cfg = secrets_blob.get("mfa", {})
        if isinstance(mfa_cfg, dict) and mfa_cfg.get("enabled") and mfa_cfg.get("totp_secret"):
            self._pending_vmk = vmk
            self._pending_secrets = secrets_blob
            return False

        self._finalize_unlock(vmk, secrets_blob)
        self._log("unlock_success", f"Vault unlocked on device ({dev.device_id}).", severity="info")
        return True

    def _finalize_unlock(self, vmk: bytes, secrets_blob: dict[str, Any]) -> None:
        self._vault_id = self._get_meta("vault_id") or str(uuid.uuid4())
        expected_digests = secrets_blob.get("record_digests")
        if not isinstance(expected_digests, dict):
            expected_digests = None
        self._entries = self._load_all_entries(vmk, expected_digests=expected_digests)
        self._secrets_blob = secrets_blob
        self._adaptive_config = AdaptivePolicyConfig.from_dict(secrets_blob.get("adaptive_config"))
        self._security_policy = SecurityPolicyConfig.from_dict(secrets_blob.get("security_policy"))
        self._vmk = vmk
        self._mfa_verified = True
        self._pending_vmk = None
        self._pending_secrets = None

        # Forward-migrate older vaults missing Ed25519 signing keys or manifest
        needs_save = False
        if not self._secrets_blob.get("signing_private_key") or not self._secrets_blob.get("signing_public_key"):
            sig_priv, sig_pub = generate_ed25519_keypair()
            self._secrets_blob["signing_private_key"] = sig_priv
            self._secrets_blob["signing_public_key"] = sig_pub
            self._set_meta("signing_public_key", sig_pub)
            needs_save = True
        if expected_digests is None:
            self._rebuild_record_manifest()
            needs_save = True
        if needs_save:
            self._save_secrets_blob()

    def _rebuild_record_manifest(self) -> None:
        conn = self._open_db()
        rows = conn.execute(
            "SELECT id, dek_nonce, wrapped_dek, payload_nonce, ciphertext, updated_at FROM credentials"
        ).fetchall()
        self._secrets_blob["record_digests"] = {
            str(r[0]): compute_record_digest(
                str(r[0]), bytes(r[1]), bytes(r[2]), bytes(r[3]), bytes(r[4]), str(r[5])
            )
            for r in rows
        }

    def complete_mfa(self, code: str) -> bool:
        """Complete Stage-2 MFA unlock with anti-replay TOTP protection and rate limiting.

        Returns True if verified via TOTP, or False if a one-time recovery code was consumed.
        """
        if not self.is_mfa_pending or self._pending_vmk is None or self._pending_secrets is None:
            raise VaultLockedError("No MFA challenge is currently pending.")
        assert self._iam is not None

        self._iam.check_rate_limit("mfa")
        mfa_cfg = self._pending_secrets.get("mfa", {})
        secret = str(mfa_cfg.get("totp_secret", ""))
        last_step = int(mfa_cfg.get("last_used_step", -1))
        recovery_hashes = list(mfa_cfg.get("recovery_hashes", []))

        try:
            ok, matched_step = verify_totp_with_step(secret, code, last_used_step=last_step)
        except TOTPReplayError as exc:
            self._log("mfa_replay_blocked", str(exc), severity="alert")
            raise InvalidMFACodeError(str(exc)) from exc

        if ok:
            self._iam.record_success("mfa")
            self._pending_secrets["mfa"]["last_used_step"] = matched_step
            self._finalize_unlock(self._pending_vmk, self._pending_secrets)
            self._save_secrets_blob()  # Persist anti-replay step
            self._log("mfa_verified", "Vault unlocked after TOTP MFA verification.", severity="info")
            return True

        # Check one-time MFA recovery code
        code_hash = hash_recovery_code(code)
        if code_hash in recovery_hashes:
            self._iam.record_success("mfa")
            recovery_hashes.remove(code_hash)
            self._pending_secrets["mfa"]["recovery_hashes"] = recovery_hashes
            self._finalize_unlock(self._pending_vmk, self._pending_secrets)
            self._save_secrets_blob()
            self._log(
                "mfa_recovery_used",
                f"Vault unlocked using one-time MFA recovery code ({len(recovery_hashes)} remaining).",
                severity="warning",
            )
            return False

        fails, lock_secs = self._iam.record_failure("mfa")
        self._log("mfa_failed", f"Invalid MFA attempt #{fails}.", severity="alert" if fails >= 3 else "warning")
        if lock_secs:
            raise RateLimitError(
                f"Invalid MFA code. Locked out for {lock_secs}s.", retry_after_seconds=lock_secs
            )
        raise InvalidMFACodeError("Invalid 6-digit authenticator code or recovery code.")

    def lock(self) -> None:
        """Wipe in-memory keys and decrypted credentials immediately."""
        was_unlocked = self.is_unlocked
        self._vmk = None
        self._entries = {}
        self._secrets_blob = {}
        self._mfa_verified = False
        self._pending_vmk = None
        self._pending_secrets = None
        if was_unlocked:
            self._log("vault_locked", "Vault locked and keys cleared from memory.", severity="info")

    # ------------------------------------------------------------------ #
    # Adaptive Security & Re-Authentication
    # ------------------------------------------------------------------ #

    def evaluate_security_action(self, action: str, *, entry_category: str = "General") -> SecurityRequirement:
        self._require_unlocked()
        assert self._iam is not None
        stats = self._iam.get_auth_stats()
        recent_fails = int(stats.get("master", {}).get("consecutive_failures", 0))
        return evaluate_action(
            action,
            self._adaptive_config,
            entry_category=entry_category,
            mfa_enabled=self.mfa_enabled,
            recent_failed_logins=recent_fails,
        )

    def verify_reauth(
        self, master_password: str, mfa_code: str = "", *, require_mfa: bool = False
    ) -> None:
        """Verify master password (and MFA code when enabled/required) with rate limiting."""
        self._require_unlocked()
        assert self._vmk is not None and self._iam is not None

        self._iam.check_rate_limit("master")
        try:
            unwrapped = self._unwrap_vmk_with_master_password(master_password)
        except (DecryptionError, CryptoError, ValueError) as exc:
            fails, lock_secs = self._iam.record_failure("master")
            self._log("reauth_failed", f"Re-authentication failed (#{fails}).", severity="warning")
            if lock_secs:
                raise RateLimitError(
                    f"Too many failed re-authentication attempts. Wait {lock_secs}s.",
                    retry_after_seconds=lock_secs,
                ) from exc
            raise InvalidPasswordError("Incorrect master password.") from exc

        if not secrets.compare_digest(unwrapped, self._vmk):
            self._iam.record_failure("master")
            raise InvalidPasswordError("Incorrect master password.")
        self._iam.record_success("master")

        if self.mfa_enabled and (require_mfa or mfa_code):
            if not mfa_code.strip():
                raise InvalidMFACodeError("A 6-digit MFA authenticator code is required for this action.")
            self._iam.check_rate_limit("mfa")
            mfa_cfg = self._secrets_blob.get("mfa", {})
            secret = str(mfa_cfg.get("totp_secret", ""))
            if not verify_totp(secret, mfa_code):
                fails, lock_secs = self._iam.record_failure("mfa")
                self._log("reauth_mfa_failed", f"Invalid MFA code during strong re-authentication (#{fails}).", severity="warning")
                if lock_secs:
                    raise RateLimitError(f"Invalid MFA code. Wait {lock_secs}s.", retry_after_seconds=lock_secs)
                raise InvalidMFACodeError("Invalid 6-digit MFA code.")
            self._iam.record_success("mfa")

    def update_adaptive_config(self, config: AdaptivePolicyConfig, master_password: str) -> None:
        self._require_unlocked()
        self.verify_reauth(master_password)
        self._adaptive_config = config
        self._secrets_blob["adaptive_config"] = config.to_dict()
        self._save_secrets_blob()
        self._log("security_settings_changed", "Adaptive security policy settings updated.", severity="info")

    # ------------------------------------------------------------------ #
    # Zero-Reset Emergency Recovery Kit & Master Password Rotation
    # ------------------------------------------------------------------ #

    def generate_emergency_recovery_kit(self) -> str:
        """Wrap VMK under a new 200-bit offline Emergency Recovery Key (zero-reset architecture)."""
        self._require_unlocked()
        assert self._vmk is not None

        recovery_key = generate_recovery_key()
        salt = generate_salt()
        rec_kek = derive_kek_argon2id(recovery_key, salt, self._default_kdf)
        wrapped = wrap_key(rec_kek, self._vmk, context="shield-vmk-recovery-v1")

        self._set_meta("recovery_salt", base64.b64encode(salt).decode("ascii"))
        self._set_meta("recovery_kdf_params", json.dumps(self._default_kdf.to_dict()))
        self._set_meta("recovery_vmk_wrapped", json.dumps(wrapped))
        self._set_meta("recovery_created_at", _utc_now())

        self._log("recovery_kit_generated", "New Emergency Recovery Kit generated (VMK wrapped).", severity="warning")
        return recovery_key

    def recover_vault_with_recovery_key(self, recovery_key_raw: str, new_master_password: str) -> None:
        """Recover access to a locked vault using ONLY the pre-generated Emergency Recovery Key."""
        if len(new_master_password) < 8:
            raise ValueError("New master password must be at least 8 characters long.")
        if not self.exists:
            raise VaultFormatError("Vault does not exist.")
        self._open_db()
        assert self._iam is not None

        self._iam.check_rate_limit("master")
        self._iam.ensure_device_not_revoked()

        rec_salt_raw = self._get_meta("recovery_salt")
        rec_kdf_raw = self._get_meta("recovery_kdf_params")
        rec_wrapped_raw = self._get_meta("recovery_vmk_wrapped")
        if not rec_salt_raw or not rec_kdf_raw or not rec_wrapped_raw:
            raise VaultError(
                "No Emergency Recovery Kit exists for this vault. Under S.H.I.E.L.D.'s zero-reset design, "
                "recovery is impossible without pre-generated recovery material."
            )

        try:
            norm_key = normalize_recovery_key(recovery_key_raw)
            params = KdfParams.from_dict(json.loads(rec_kdf_raw))
            salt = base64.b64decode(rec_salt_raw, validate=True)
            wrapped = json.loads(rec_wrapped_raw)
            rec_kek = derive_kek_argon2id(norm_key, salt, params)
            vmk = unwrap_key(rec_kek, wrapped, context="shield-vmk-recovery-v1")
            secrets_blob = self._load_secrets_blob(vmk)
        except (DecryptionError, CryptoError, ValueError) as exc:
            fails, lock_secs = self._iam.record_failure("master")
            self._log("recovery_failed", f"Failed vault recovery attempt (#{fails}).", severity="alert")
            if lock_secs:
                raise RateLimitError(
                    f"Invalid Emergency Recovery Key. Locked out for {lock_secs}s.",
                    retry_after_seconds=lock_secs,
                ) from exc
            raise InvalidPasswordError("Invalid Emergency Recovery Key.") from exc

        # Re-wrap VMK under new master password with fresh salt
        new_salt = generate_salt()
        new_kek = derive_kek_argon2id(new_master_password, new_salt, self._default_kdf)
        new_wrapped = wrap_key(new_kek, vmk, context="shield-vmk-master-v1")
        self._set_meta("kdf_params", json.dumps(self._default_kdf.to_dict()))
        self._set_meta("master_salt", base64.b64encode(new_salt).decode("ascii"))
        self._set_meta("master_vmk_wrapped", json.dumps(new_wrapped))

        assert self._iam is not None
        self._iam.record_success("master")
        self._finalize_unlock(vmk, secrets_blob)
        self._log(
            "vault_recovered",
            "Vault recovered via Emergency Recovery Key and master password rotated.",
            severity="alert",
        )

    def change_master_password(self, current_password: str, new_password: str) -> None:
        self._require_unlocked()
        assert self._vmk is not None
        if len(new_password) < 8:
            raise ValueError("New master password must be at least 8 characters long.")
        self.verify_reauth(current_password)
        self.create_rolling_snapshot()

        new_salt = generate_salt()
        new_kek = derive_kek_argon2id(new_password, new_salt, self._default_kdf)
        new_wrapped = wrap_key(new_kek, self._vmk, context="shield-vmk-master-v1")

        self._set_meta("kdf_params", json.dumps(self._default_kdf.to_dict()))
        self._set_meta("master_salt", base64.b64encode(new_salt).decode("ascii"))
        self._set_meta("master_vmk_wrapped", json.dumps(new_wrapped))
        self._log("master_password_changed", "Master password rotated and VMK re-wrapped.", severity="warning")

    # ------------------------------------------------------------------ #
    # MFA Management
    # ------------------------------------------------------------------ #

    def enable_mfa(self, totp_secret: str, verification_code: str) -> list[str]:
        self._require_unlocked()
        norm_secret = normalize_totp_secret(totp_secret)
        ok, step = verify_totp_with_step(norm_secret, verification_code, last_used_step=-1)
        if not ok:
            raise InvalidMFACodeError("Verification code did not match. Check your authenticator clock.")

        recovery_codes = generate_recovery_codes(8)
        self._secrets_blob["mfa"] = {
            "enabled": True,
            "totp_secret": norm_secret,
            "last_used_step": step,
            "recovery_hashes": [hash_recovery_code(c) for c in recovery_codes],
        }
        self._save_secrets_blob()
        self._log("mfa_enabled", "Vault TOTP Multi-Factor Authentication enabled.", severity="info")
        return recovery_codes

    def disable_mfa(self, current_master_password: str) -> None:
        self._require_unlocked()
        self.verify_reauth(current_master_password)
        self._secrets_blob["mfa"] = {
            "enabled": False,
            "totp_secret": "",
            "last_used_step": -1,
            "recovery_hashes": [],
        }
        self._save_secrets_blob()
        self._log("mfa_disabled", "Vault MFA disabled.", severity="warning")

    # ------------------------------------------------------------------ #
    # Trusted Devices & Audit Log Accessors
    # ------------------------------------------------------------------ #

    def list_devices(self) -> list[TrustedDevice]:
        self._require_unlocked()
        assert self._iam is not None
        return self._iam.list_devices()

    def register_external_device(self, name: str, os_info: str, master_password: str) -> TrustedDevice:
        self._require_unlocked()
        self.verify_reauth(master_password)
        assert self._iam is not None
        dev = self._iam.register_device(name, os_info)
        self._log("device_registered", f"Manually trusted device '{dev.name}' ({dev.device_id}).", severity="info")
        return dev

    def revoke_device(self, device_id: str, master_password: str) -> bool:
        self._require_unlocked()
        self.verify_reauth(master_password)
        assert self._iam is not None
        ok = self._iam.set_device_status(device_id, "revoked")
        if ok:
            self._log("device_revoked", f"Revoked device {device_id}.", severity="alert")
        return ok

    def trust_device(self, device_id: str, master_password: str) -> bool:
        self._require_unlocked()
        self.verify_reauth(master_password)
        assert self._iam is not None
        ok = self._iam.set_device_status(device_id, "trusted")
        if ok:
            self._log("device_retrusted", f"Restored trust for device {device_id}.", severity="warning")
        return ok

    def get_auth_stats(self) -> dict[str, dict[str, object]]:
        self._open_db()
        assert self._iam is not None
        return self._iam.get_auth_stats()

    def list_audit_events(self, limit: int = 200, severity: str = "All") -> list[AuditEvent]:
        self._require_unlocked()
        assert self._audit is not None
        return self._audit.list_events(limit=limit, severity=severity)

    def recent_security_alerts(self, limit: int = 10) -> list[AuditEvent]:
        self._require_unlocked()
        assert self._audit is not None
        return self._audit.recent_alerts(limit=limit)

    def verify_audit_log_integrity(self) -> tuple[bool, str]:
        self._open_db()
        assert self._audit is not None
        sig_pub = (
            str(self._secrets_blob.get("signing_public_key", ""))
            if self.is_unlocked
            else (self._get_meta("signing_public_key") or "")
        )
        vid = self._vault_id if self.is_unlocked else (self._get_meta("vault_id") or "")
        return self._audit.verify_chain(signing_public_key_b64=sig_pub, vault_id=vid)

    def export_signed_audit_proof(self, dest_path: str | Path) -> Path:
        self._require_unlocked()
        assert self._audit is not None
        sig_pub = str(self._secrets_blob.get("signing_public_key", ""))
        out = self._audit.export_signed_proof(dest_path, sig_pub, self._vault_id)
        self._log("audit_proof_exported", "Exported Ed25519-signed non-repudiation audit proof.", severity="info")
        return out

    def check_sqlite_integrity(self) -> tuple[bool, str]:
        """Run SQLite PRAGMA integrity_check to detect database corruption."""
        conn = self._open_db()
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        msgs = [str(r[0]) for r in rows]
        if msgs == ["ok"]:
            return True, "SQLite B-tree integrity check passed (ok)."
        return False, "; ".join(msgs[:5])

    def verify_vault_integrity(self) -> tuple[bool, str]:
        """Verify SQLite B-tree, per-record anti-rollback manifest, and Ed25519 audit chain."""
        self._require_unlocked()
        assert self._vmk is not None
        db_ok, db_msg = self.check_sqlite_integrity()
        if not db_ok:
            return False, f"SQLite corruption: {db_msg}"
        try:
            expected = self._secrets_blob.get("record_digests")
            self._load_all_entries(self._vmk, expected_digests=expected if isinstance(expected, dict) else None)
        except VaultIntegrityError as exc:
            return False, str(exc)
        chain_ok, chain_msg = self.verify_audit_log_integrity()
        if not chain_ok:
            return False, chain_msg
        return True, f"All checks passed: SQLite OK • {len(self._entries)} record digests verified • {chain_msg}"

    def create_rolling_snapshot(self, max_keep: int = 5) -> Path:
        """Create an automatic online SQLite backup snapshot for Availability / Disaster Recovery."""
        self._require_unlocked()
        conn = self._open_db()
        snap_dir = self.path.parent / "snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%fZ")
        snap_path = snap_dir / f"{self.path.stem}_snap_{stamp}.db"
        dst = sqlite3.connect(str(snap_path))
        try:
            conn.backup(dst)
        finally:
            dst.close()
        restrict_file_permissions(snap_path)

        # Prune oldest snapshots beyond max_keep
        snaps = sorted(snap_dir.glob(f"{self.path.stem}_snap_*.db"), key=lambda p: p.name, reverse=True)
        for old in snaps[max_keep:]:
            try:
                old.unlink()
            except OSError:
                pass
        return snap_path

    def list_rolling_snapshots(self) -> list[Path]:
        snap_dir = self.path.parent / "snapshots"
        if not snap_dir.is_dir():
            return []
        return sorted(snap_dir.glob(f"{self.path.stem}_snap_*.db"), key=lambda p: p.name, reverse=True)

    def evaluate_five_pillars(self) -> list[dict[str, str]]:
        """Evaluate live compliance across the 5 Pillars of Cybersecurity."""
        self._require_unlocked()
        db_ok, _ = self.check_sqlite_integrity()
        chain_ok, chain_msg = self.verify_audit_log_integrity()
        manifest_ok = True
        try:
            assert self._vmk is not None
            self._load_all_entries(self._vmk, expected_digests=self._secrets_blob.get("record_digests"))
        except VaultIntegrityError:
            manifest_ok = False

        snaps = self.list_rolling_snapshots()
        last_bak = str(self._secrets_blob.get("last_backup_at", ""))
        has_rec = self.has_recovery_kit
        avail_strong = has_rec and (bool(last_bak) or bool(snaps))

        devices = self.list_devices()
        trusted_devs = sum(1 for d in devices if d.status == "trusted")

        return [
            {
                "pillar": "Confidentiality",
                "status": "STRONG",
                "detail": "Argon2id (64 MiB) + AES-256-GCM per-record DEKs • RAM-only keys • Auto-clear clipboard",
            },
            {
                "pillar": "Integrity",
                "status": "STRONG" if (db_ok and manifest_ok) else "ALERT",
                "detail": (
                    f"AES-GCM tags + anti-rollback manifest ({len(self._entries)} records) + SQLite PRAGMA OK"
                    if (db_ok and manifest_ok)
                    else "TAMPER OR CORRUPTION DETECTED — Inspect immediately!"
                ),
            },
            {
                "pillar": "Availability",
                "status": "STRONG" if avail_strong else "ATTENTION",
                "detail": (
                    f"Recovery Kit: {'READY' if has_rec else 'NOT SET'} • "
                    f"Backups: {last_bak or 'None yet'} • Rolling Snapshots: {len(snaps)}"
                ),
            },
            {
                "pillar": "Authenticity",
                "status": "STRONG" if self.mfa_enabled else "ATTENTION",
                "detail": (
                    f"MFA Anti-Replay: {'ON' if self.mfa_enabled else 'OFF'} • "
                    f"Trusted Devices: {trusted_devs} • Ed25519 Source ID: {self.signing_fingerprint}"
                ),
            },
            {
                "pillar": "Non-Repudiation",
                "status": "STRONG" if chain_ok else "ALERT",
                "detail": chain_msg,
            },
        ]

    def record_credential_event(self, event_type: str, entry_id: str = "", severity: str = "info") -> None:
        if self.is_unlocked:
            tag = f" [rec:{entry_id[:8]}]" if entry_id else ""
            self._log(event_type, f"{event_type.replace('_', ' ').title()}{tag}.", severity=severity)

    # ------------------------------------------------------------------ #
    # Credential CRUD, Tags, Favorites, Search & Reuse Protection
    # ------------------------------------------------------------------ #

    def list_entries(
        self,
        query: str = "",
        category: str = "All",
        entry_type: str = "All",
        tag: str = "All",
        favorites_only: bool = False,
    ) -> list[VaultEntry]:
        self._require_unlocked()
        q = query.strip().lower()
        results: list[VaultEntry] = []
        for entry in self._entries.values():
            if favorites_only and not entry.favorite:
                continue
            if category and category != "All" and entry.category != category:
                continue
            if entry_type and entry_type != "All" and entry.entry_type != entry_type:
                continue
            if tag and tag != "All" and tag.lower() not in entry.tags:
                continue
            if q:
                cf_text = " ".join(f"{k} {v}" for k, v in entry.custom_fields.items())
                haystack = " ".join(
                    (
                        entry.title,
                        entry.entry_type,
                        entry.username,
                        entry.url,
                        entry.category,
                        " ".join(entry.tags),
                        entry.notes,
                        cf_text,
                    )
                ).lower()
                if q not in haystack:
                    continue
            results.append(entry)
        return sorted(results, key=lambda e: (not e.favorite, e.title.lower(), e.username.lower()))

    def all_tags(self) -> list[str]:
        self._require_unlocked()
        tags: set[str] = set()
        for e in self._entries.values():
            tags.update(e.tags)
        return sorted(tags)

    def get_entry(self, entry_id: str) -> VaultEntry | None:
        self._require_unlocked()
        return self._entries.get(entry_id)

    def count(self) -> int:
        self._require_unlocked()
        return len(self._entries)

    def find_password_reuse(
        self, candidate_password: str, exclude_entry_id: str | None = None
    ) -> list[VaultEntry]:
        self._require_unlocked()
        return check_password_reuse(
            list(self._entries.values()), candidate_password, exclude_entry_id=exclude_entry_id
        )

    def add_entry(
        self,
        title: str,
        *,
        entry_type: str = "Website",
        category: str = "General",
        tags: list[str] | None = None,
        favorite: bool = False,
        username: str = "",
        password: str = "",
        url: str = "",
        totp_secret: str = "",
        passkey_enabled: bool = False,
        custom_fields: dict[str, str] | None = None,
        notes: str = "",
        site_policy: str = "",
    ) -> VaultEntry:
        self._require_unlocked()
        if not title.strip():
            raise ValueError("Title is required.")
        entry = VaultEntry.create(
            title=title,
            entry_type=entry_type,
            category=category,
            tags=tags,
            favorite=favorite,
            username=username,
            password=password,
            url=url,
            totp_secret=totp_secret,
            passkey_enabled=passkey_enabled,
            custom_fields=custom_fields,
            notes=notes,
            site_policy=site_policy,
        )
        self._entries[entry.id] = entry
        self._persist_entry(entry)
        self._log("entry_created", f"Created {entry.entry_type} credential [rec:{entry.id[:8]}].", severity="info")
        return entry

    def update_entry(
        self,
        entry_id: str,
        *,
        title: str,
        entry_type: str = "Website",
        category: str = "General",
        tags: list[str] | None = None,
        favorite: bool = False,
        username: str = "",
        password: str = "",
        url: str = "",
        totp_secret: str = "",
        passkey_enabled: bool = False,
        custom_fields: dict[str, str] | None = None,
        notes: str = "",
        site_policy: str = "",
    ) -> VaultEntry:
        self._require_unlocked()
        if not title.strip():
            raise ValueError("Title is required.")
        entry = self._entries.get(entry_id)
        if entry is None:
            raise KeyError(f"Entry not found: {entry_id}")

        clean_totp = normalize_totp_secret(totp_secret) if totp_secret.strip() else ""
        now = _utc_now()
        pwd_changed = password != entry.password

        entry.title = title.strip()
        entry.entry_type = entry_type if entry_type in ENTRY_TYPES else "Website"
        entry.category = category if category in CATEGORIES else "General"
        entry.tags = _normalize_tags(tags if tags is not None else entry.tags)
        entry.favorite = bool(favorite)
        entry.username = username.strip()
        entry.password = password
        entry.url = url.strip()
        entry.totp_secret = clean_totp
        entry.passkey_enabled = bool(passkey_enabled)
        if custom_fields is not None:
            entry.custom_fields = {str(k).strip(): str(v) for k, v in custom_fields.items() if str(k).strip()}
        entry.notes = notes
        entry.site_policy = site_policy.strip()
        entry.updated_at = now
        if pwd_changed:
            entry.password_updated_at = now

        self._persist_entry(entry)
        if pwd_changed:
            self._log("password_changed", f"Updated password for credential [rec:{entry.id[:8]}].", severity="info")
        else:
            self._log("entry_updated", f"Updated credential [rec:{entry.id[:8]}].", severity="info")
        return entry

    def delete_entry(self, entry_id: str) -> bool:
        self._require_unlocked()
        entry = self._entries.pop(entry_id, None)
        if entry is None:
            return False
        conn = self._open_db()
        conn.execute("DELETE FROM credentials WHERE id = ?", (entry_id,))
        conn.commit()
        deleted = self._secrets_blob.setdefault("deleted_ids", {})
        deleted[entry_id] = _utc_now()
        self._secrets_blob.setdefault("record_digests", {}).pop(entry_id, None)
        self._save_secrets_blob()
        self._log("entry_deleted", f"Deleted credential [rec:{entry.id[:8]}].", severity="warning")
        return True

    # ------------------------------------------------------------------ #
    # Backups, Restore Verification, Portability & E2EE Sync/Share
    # ------------------------------------------------------------------ #

    def export_encrypted_backup_file(self, dest_path: str | Path, master_password: str) -> Path:
        self._require_unlocked()
        self.verify_reauth(master_password)
        out = create_encrypted_backup(
            list(self._entries.values()),
            self._secrets_blob.get("deleted_ids", {}),
            self._vault_id,
            master_password,
            dest_path,
            kdf_params=self._default_kdf,
            signing_private_key_b64=str(self._secrets_blob.get("signing_private_key", "")),
            signing_public_key_b64=str(self._secrets_blob.get("signing_public_key", "")),
        )
        self._secrets_blob["last_backup_at"] = _utc_now()
        self._save_secrets_blob()
        self._log("backup_created", f"Ed25519-signed encrypted backup exported ({len(self._entries)} entries).", severity="info")
        return out

    def create_versioned_backup_in_dir(self, backup_dir: str | Path, master_password: str) -> Path:
        self._require_unlocked()
        self.verify_reauth(master_password)
        out = create_versioned_backup(
            list(self._entries.values()),
            self._secrets_blob.get("deleted_ids", {}),
            self._vault_id,
            master_password,
            backup_dir,
            kdf_params=self._default_kdf,
            signing_private_key_b64=str(self._secrets_blob.get("signing_private_key", "")),
            signing_public_key_b64=str(self._secrets_blob.get("signing_public_key", "")),
        )
        self._secrets_blob["last_backup_at"] = _utc_now()
        self._save_secrets_blob()
        self._log("backup_created", f"Versioned Ed25519-signed backup created ({len(self._entries)} entries).", severity="info")
        return out

    def test_backup_restore_integrity(self, backup_path: str | Path, passphrase: str) -> dict[str, Any]:
        result = verify_backup_integrity(backup_path, passphrase)
        if self.is_unlocked:
            sev = "info" if result["valid"] else "alert"
            self._log("backup_verified", f"Backup integrity verification: {result['message']}", severity=sev)
        return result

    def restore_from_encrypted_backup(
        self, backup_path: str | Path, passphrase: str, merge: bool = True
    ) -> dict[str, int]:
        """Restore entries from an encrypted backup (merge by default, or replace)."""
        self._require_unlocked()
        _header, payload, _meta = decrypt_encrypted_backup(backup_path, passphrase)
        self.create_rolling_snapshot()
        raw_entries = payload.get("entries", [])
        added = 0
        updated = 0
        if not merge:
            for eid in list(self._entries.keys()):
                self.delete_entry(eid)

        for item in raw_entries:
            entry = VaultEntry.from_dict(item)
            existing = self._entries.get(entry.id)
            if existing is None:
                self._entries[entry.id] = entry
                self._persist_entry(entry, save_manifest=False)
                added += 1
            elif entry.updated_at > existing.updated_at:
                self._entries[entry.id] = entry
                self._persist_entry(entry, save_manifest=False)
                updated += 1

        self._save_secrets_blob()
        self._log(
            "backup_restored",
            f"Restored verified encrypted backup (added {added}, updated {updated}).",
            severity="warning",
        )
        return {"added": added, "updated": updated, "total": len(self._entries)}

    def export_plaintext_json_file(self, dest_path: str | Path, master_password: str, mfa_code: str = "") -> Path:
        self._require_unlocked()
        self.verify_reauth(master_password, mfa_code=mfa_code, require_mfa=self.mfa_enabled)
        out = export_plaintext_json(list(self._entries.values()), dest_path)
        self._log(
            "export_plaintext_json",
            f"SENSITIVE plaintext JSON exported ({len(self._entries)} entries).",
            severity="alert",
        )
        return out

    def import_plaintext_json_file(self, src_path: str | Path) -> tuple[int, int]:
        self._require_unlocked()
        items = parse_plaintext_json(src_path)
        existing_sigs = {(e.title.lower(), e.username.lower(), e.url.lower()) for e in self._entries.values()}
        imported = 0
        skipped = 0
        for item in items:
            entry = VaultEntry.from_dict(item)
            sig = (entry.title.lower(), entry.username.lower(), entry.url.lower())
            if sig in existing_sigs:
                skipped += 1
                continue
            entry.id = str(uuid.uuid4())
            self._entries[entry.id] = entry
            self._persist_entry(entry)
            existing_sigs.add(sig)
            imported += 1
        if imported:
            self._log("import_json", f"Imported {imported} entries from JSON.", severity="info")
        return imported, skipped

    def import_google_items(self, items: list[GoogleCsvItem], skip_duplicates: bool = True) -> tuple[int, int]:
        self._require_unlocked()
        existing_sigs = {(e.title.lower(), e.username.lower(), e.url.lower()) for e in self._entries.values()}
        imported = 0
        skipped = 0
        for item in items:
            sig = (item.title.lower(), item.username.lower(), item.url.lower())
            if skip_duplicates and sig in existing_sigs:
                skipped += 1
                continue
            entry = VaultEntry.create(
                title=item.title,
                entry_type="Website",
                category="General",
                username=item.username,
                password=item.password,
                url=item.url,
                notes=item.notes,
            )
            self._entries[entry.id] = entry
            self._persist_entry(entry)
            existing_sigs.add(sig)
            imported += 1
        if imported:
            self._log("import_google_csv", f"Imported {imported} entries from Google CSV.", severity="info")
        return imported, skipped

    def share_entry_for_public_key(self, entry_id: str, recipient_public_key: str) -> str:
        self._require_unlocked()
        entry = self._entries.get(entry_id)
        if entry is None:
            raise KeyError(f"Entry not found: {entry_id}")
        packet = encrypt_entry_for_public_key(
            asdict(entry),
            recipient_public_key,
            sender_signing_priv_b64=str(self._secrets_blob.get("signing_private_key", "")),
            sender_signing_pub_b64=str(self._secrets_blob.get("signing_public_key", "")),
        )
        self._log("e2ee_share_created", f"Created Ed25519-signed X25519 E2EE share [rec:{entry.id[:8]}].", severity="info")
        return packet

    def share_entry_with_passphrase(self, entry_id: str, passphrase: str) -> str:
        self._require_unlocked()
        entry = self._entries.get(entry_id)
        if entry is None:
            raise KeyError(f"Entry not found: {entry_id}")
        packet = encrypt_entry_with_passphrase(
            asdict(entry),
            passphrase,
            sender_signing_priv_b64=str(self._secrets_blob.get("signing_private_key", "")),
            sender_signing_pub_b64=str(self._secrets_blob.get("signing_public_key", "")),
        )
        self._log("e2ee_share_created", f"Created Ed25519-signed passphrase E2EE share [rec:{entry.id[:8]}].", severity="info")
        return packet

    def import_e2ee_packet(self, token: str, passphrase: str = "") -> VaultEntry:
        self._require_unlocked()
        cleaned = token.strip()
        if cleaned.startswith(SHARE_PK_PREFIX):
            data, sender_fp = decrypt_entry_with_private_key(
                cleaned, str(self._secrets_blob.get("e2ee_private_key", ""))
            )
        elif cleaned.startswith(SHARE_PW_PREFIX):
            if not passphrase:
                raise ValueError("A share passphrase is required to decrypt this packet.")
            data, sender_fp = decrypt_entry_with_passphrase(cleaned, passphrase)
        else:
            raise ValueError("Unrecognized S.H.I.E.L.D. E2EE packet format.")

        self.last_e2ee_sender_fingerprint = sender_fp
        entry = VaultEntry.from_dict(data)
        entry.id = str(uuid.uuid4())
        now = _utc_now()
        entry.created_at = now
        entry.updated_at = now
        self._entries[entry.id] = entry
        self._persist_entry(entry)
        self._log(
            "e2ee_share_imported",
            f"Verified & imported E2EE credential [rec:{entry.id[:8]}] from {sender_fp}.",
            severity="info",
        )
        return entry

    def sync_with_remote(self, remote_path: str | Path, master_password: str) -> dict[str, int]:
        """Zero-knowledge E2EE sync & conflict-safe merge with an encrypted `.shield.enc` file."""
        self._require_unlocked()
        self.verify_reauth(master_password)

        remote = Path(remote_path)
        if remote.resolve() == self.path.resolve():
            raise ValueError("Sync destination must be a separate encrypted file from the local SQLite database.")

        added_local = 0
        updated_local = 0
        removed_local = 0
        local_deleted: dict[str, str] = dict(self._secrets_blob.get("deleted_ids", {}))

        if remote.is_file():
            _header, remote_payload, _meta = decrypt_encrypted_backup(remote, master_password)
            remote_entries = [VaultEntry.from_dict(item) for item in remote_payload.get("entries", [])]
            remote_deleted = remote_payload.get("deleted_ids", {})
            if not isinstance(remote_deleted, dict):
                remote_deleted = {}

            merged_deleted = dict(local_deleted)
            for eid, ts in remote_deleted.items():
                ts_str = str(ts)
                if eid not in merged_deleted or ts_str > merged_deleted[eid]:
                    merged_deleted[eid] = ts_str

            remote_by_id = {e.id: e for e in remote_entries}
            all_ids = set(self._entries.keys()) | set(remote_by_id.keys())
            conn = self._open_db()

            for eid in all_ids:
                l_entry = self._entries.get(eid)
                r_entry = remote_by_id.get(eid)
                del_ts = merged_deleted.get(eid, "")

                if l_entry and r_entry:
                    winner = r_entry if r_entry.updated_at > l_entry.updated_at else l_entry
                    if del_ts and del_ts > winner.updated_at:
                        self._entries.pop(eid, None)
                        conn.execute("DELETE FROM credentials WHERE id = ?", (eid,))
                        self._secrets_blob.setdefault("record_digests", {}).pop(eid, None)
                        removed_local += 1
                    elif winner is r_entry and r_entry.updated_at > l_entry.updated_at:
                        self._entries[eid] = r_entry
                        self._persist_entry(r_entry, save_manifest=False)
                        updated_local += 1
                elif l_entry:
                    if del_ts and del_ts > l_entry.updated_at:
                        self._entries.pop(eid, None)
                        conn.execute("DELETE FROM credentials WHERE id = ?", (eid,))
                        self._secrets_blob.setdefault("record_digests", {}).pop(eid, None)
                        removed_local += 1
                elif r_entry:
                    if not (del_ts and del_ts > r_entry.updated_at):
                        self._entries[eid] = r_entry
                        self._persist_entry(r_entry, save_manifest=False)
                        added_local += 1

            conn.commit()
            local_deleted = merged_deleted

        self._secrets_blob["deleted_ids"] = local_deleted
        self._secrets_blob["sync_path"] = str(remote)
        self._secrets_blob["last_backup_at"] = _utc_now()
        self._save_secrets_blob()

        create_encrypted_backup(
            list(self._entries.values()),
            local_deleted,
            self._vault_id,
            master_password,
            remote,
            kdf_params=self._default_kdf,
            signing_private_key_b64=str(self._secrets_blob.get("signing_private_key", "")),
            signing_public_key_b64=str(self._secrets_blob.get("signing_public_key", "")),
        )
        self._log(
            "e2ee_sync",
            f"Zero-knowledge signed E2EE sync complete (added {added_local}, updated {updated_local}, removed {removed_local}).",
            severity="info",
        )
        return {
            "added_local": added_local,
            "updated_local": updated_local,
            "removed_local": removed_local,
            "total_entries": len(self._entries),
        }

    # ------------------------------------------------------------------ #
    # Governance: Policies, Risk Management, Incident Response, Patching & DR
    # ------------------------------------------------------------------ #

    def update_security_policy(self, policy: SecurityPolicyConfig, master_password: str) -> None:
        self._require_unlocked()
        self.verify_reauth(master_password)
        self._security_policy = policy
        self._secrets_blob["security_policy"] = policy.to_dict()
        self._save_secrets_blob()
        self._log(
            "policy_updated",
            f"Security policy updated (min_len={policy.min_password_length}, reuse={policy.reuse_policy}).",
            severity="warning",
        )

    def evaluate_policy_compliance(self) -> tuple[int, list[PolicyCheckResult]]:
        self._require_unlocked()
        return evaluate_policy_compliance(
            list(self._entries.values()),
            self._security_policy,
            vault_mfa_enabled=self.mfa_enabled,
            has_recovery_kit=self.has_recovery_kit,
            last_backup_at=str(self._secrets_blob.get("last_backup_at", "")),
        )

    def get_patch_posture(self) -> list[PatchCheckItem]:
        kdf_raw = self._get_meta("kdf_params")
        mem_kib = self._default_kdf.memory_cost
        iters = self._default_kdf.iterations
        if kdf_raw:
            try:
                p = KdfParams.from_dict(json.loads(kdf_raw))
                mem_kib = p.memory_cost
                iters = p.iterations
            except Exception:
                pass
        return check_patch_posture(kdf_memory_kib=mem_kib, kdf_iterations=iters)

    def list_risk_register(self) -> list[RiskRecord]:
        self._require_unlocked()
        _score, checks = self.evaluate_policy_compliance()
        patches = self.get_patch_posture()
        chain_ok, _ = self.verify_audit_log_integrity()
        stats = self.get_auth_stats()
        failed_logins = int(stats.get("master", {}).get("total_failures", 0))

        auto_risks = synthesize_auto_risks(
            list(self._entries.values()),
            checks,
            patches,
            chain_ok=chain_ok,
            failed_logins=failed_logins,
        )

        saved_raw = self._secrets_blob.get("risk_register", [])
        saved_by_id: dict[str, RiskRecord] = {}
        if isinstance(saved_raw, list):
            for item in saved_raw:
                if isinstance(item, dict):
                    rec = RiskRecord.from_dict(item)
                    saved_by_id[rec.id] = rec

        merged: list[RiskRecord] = []
        seen_ids: set[str] = set()
        for ar in auto_risks:
            if ar.id in saved_by_id:
                # Preserve user's tracked status/owner_note for auto-detected risks
                ar.status = saved_by_id[ar.id].status
                ar.owner_note = saved_by_id[ar.id].owner_note
            merged.append(ar)
            seen_ids.add(ar.id)

        for rid, rec in saved_by_id.items():
            if rid not in seen_ids and not rec.auto_detected:
                merged.append(rec)

        merged.sort(key=lambda r: (r.status == "Closed", -r.score, r.title.lower()))
        return merged

    def upsert_risk(self, risk: RiskRecord) -> RiskRecord:
        self._require_unlocked()
        risk.updated_at = _utc_now()
        saved_raw = self._secrets_blob.get("risk_register", [])
        items = [dict(x) for x in saved_raw if isinstance(x, dict) and x.get("id") != risk.id]
        items.append(asdict(risk))
        self._secrets_blob["risk_register"] = items
        self._save_secrets_blob()
        self._log(
            "risk_updated",
            f"Risk register item [{risk.id}] set to {risk.status} (score {risk.score}/25).",
            severity="warning" if risk.status == "Accepted" else "info",
        )
        return risk

    def list_incidents(self) -> list[IncidentCase]:
        self._require_unlocked()
        raw = self._secrets_blob.get("incidents", [])
        if not isinstance(raw, list):
            return []
        cases = [IncidentCase.from_dict(item) for item in raw if isinstance(item, dict)]
        cases.sort(key=lambda i: (i.phase == "Closed", i.opened_at), reverse=False)
        return cases

    def open_incident(self, playbook_name: str, custom_title: str = "") -> IncidentCase:
        self._require_unlocked()
        case = IncidentCase.create_from_playbook(playbook_name, custom_title=custom_title)
        raw = self._secrets_blob.setdefault("incidents", [])
        if not isinstance(raw, list):
            raw = []
            self._secrets_blob["incidents"] = raw
        raw.append(asdict(case))
        self._save_secrets_blob()
        self._log(
            "incident_opened",
            f"Opened IR case [{case.id}] ({case.severity.upper()} • playbook: {case.playbook}).",
            severity="alert",
        )
        return case

    def update_incident(self, case: IncidentCase) -> IncidentCase:
        self._require_unlocked()
        if case.phase == "Closed" and not case.closed_at:
            case.closed_at = _utc_now()
        raw = self._secrets_blob.get("incidents", [])
        updated = [dict(x) for x in raw if isinstance(x, dict) and x.get("id") != case.id]
        updated.append(asdict(case))
        self._secrets_blob["incidents"] = updated
        self._save_secrets_blob()
        self._log(
            "incident_updated",
            f"Updated IR case [{case.id}] -> phase: {case.phase}.",
            severity="info" if case.phase == "Closed" else "warning",
        )
        return case

    def execute_emergency_containment(
        self, master_password: str, *, revoke_other_devices: bool = True
    ) -> dict[str, Any]:
        """Deterministic IR containment: forensic snapshot + revoke other devices + signed alert."""
        self._require_unlocked()
        self.verify_reauth(master_password)
        assert self._iam is not None

        snap = self.create_rolling_snapshot()
        revoked = 0
        if revoke_other_devices:
            for dev in self._iam.list_devices():
                if not dev.is_current and dev.status != "revoked":
                    self._iam.set_device_status(dev.device_id, "revoked")
                    revoked += 1

        self._log(
            "emergency_containment",
            f"Emergency IR containment executed: snapshot preserved, {revoked} other device(s) revoked.",
            severity="critical",
        )
        return {"snapshot_path": str(snap), "revoked_devices": revoked}

    def run_dr_readiness_drill(self) -> dict[str, Any]:
        """Execute a live, non-destructive Disaster Recovery Readiness Drill."""
        self._require_unlocked()
        assert self._vmk is not None
        checks: list[dict[str, str]] = []

        # 1. SQLite B-Tree integrity
        db_ok, db_msg = self.check_sqlite_integrity()
        checks.append({"name": "SQLite B-Tree Integrity", "status": "PASS" if db_ok else "FAIL", "detail": db_msg})

        # 2. Anti-rollback record manifest
        try:
            self._load_all_entries(self._vmk, expected_digests=self._secrets_blob.get("record_digests"))
            checks.append(
                {
                    "name": "Per-Record Integrity Manifest",
                    "status": "PASS",
                    "detail": f"All {len(self._entries)} encrypted records match VMK-authenticated SHA-256 digests.",
                }
            )
            man_ok = True
        except VaultIntegrityError as exc:
            checks.append({"name": "Per-Record Integrity Manifest", "status": "FAIL", "detail": str(exc)})
            man_ok = False

        # 3. Ed25519 Non-Repudiation Audit Chain
        ch_ok, ch_msg = self.verify_audit_log_integrity()
        checks.append({"name": "Ed25519 Signed Audit Chain", "status": "PASS" if ch_ok else "FAIL", "detail": ch_msg})

        # 4. Zero-Reset Recovery Kit readiness
        rec_ok = self.has_recovery_kit
        checks.append(
            {
                "name": "Zero-Reset Emergency Recovery Kit",
                "status": "PASS" if rec_ok else "WARN",
                "detail": "Recovery Key VMK wrap present." if rec_ok else "Not generated yet — generate in Backup & Recovery.",
            }
        )

        # 5. Live Rolling Snapshot creation & verification
        snap_ok = False
        snap_detail = ""
        try:
            snap = self.create_rolling_snapshot()
            sconn = sqlite3.connect(str(snap))
            try:
                res = sconn.execute("PRAGMA integrity_check").fetchone()
                snap_ok = bool(res and res[0] == "ok")
                snap_detail = f"Created & verified snapshot ({snap.name}) — SQLite check OK."
            finally:
                sconn.close()
        except Exception as exc:
            snap_detail = f"Snapshot test failed: {exc}"
        checks.append({"name": "Rolling Snapshot Backup Test", "status": "PASS" if snap_ok else "FAIL", "detail": snap_detail})

        has_fail = any(c["status"] == "FAIL" for c in checks)
        has_warn = any(c["status"] == "WARN" for c in checks)
        overall = "FAIL" if has_fail else ("PASS WITH WARNINGS" if has_warn else "PASS")
        result = {"executed_at": _utc_now(), "overall_status": overall, "checks": checks}

        self._secrets_blob["last_dr_drill"] = result
        self._save_secrets_blob()
        self._log(
            "dr_drill_completed",
            f"Disaster Recovery Readiness Drill completed: {overall}.",
            severity="info" if overall == "PASS" else ("warning" if not has_fail else "critical"),
        )
        return result

    @property
    def last_dr_drill(self) -> dict[str, Any] | None:
        self._require_unlocked()
        val = self._secrets_blob.get("last_dr_drill")
        return val if isinstance(val, dict) else None

    def export_governance_report(self, dest_path: str | Path) -> Path:
        self._require_unlocked()
        score, checks = self.evaluate_policy_compliance()
        md = render_governance_report_markdown(
            policy_score=score,
            policy_checks=checks,
            risks=self.list_risk_register(),
            incidents=self.list_incidents(),
            patches=self.get_patch_posture(),
            dr_drill=self.last_dr_drill,
        )
        out = Path(dest_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        restrict_file_permissions(out)
        self._log("governance_report_exported", "Exported redacted Governance/Risk/IR/Patch report.", severity="info")
        return out
