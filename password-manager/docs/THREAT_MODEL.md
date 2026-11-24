# P.U.L.S.E. Password Vault (S.H.I.E.L.D. / V.A.U.L.T.) — STRIDE Threat Model

This document defines the security model, trust boundaries, honest limitations, and detection mechanisms for the password vault module.

## Trust Boundaries
1. **TB-1 (Disk / File System):** Untrusted at rest (`shield_vault.db`, `.shield.enc` backups, sync folders). Only authenticated ciphertext and non-secret metadata may reside here.
2. **TB-2 (Process Memory / RAM):** Trusted *only* while unlocked on a non-compromised host. Keys (`VMK`, `DEKs`) are never written to disk in plaintext and are dropped on lock.
3. **TB-3 (Sync / Cloud Storage):** Treated as fully hostile (honest-but-curious or actively tampering). Only Argon2id + AES-256-GCM + Ed25519-signed blobs cross this boundary.
4. **TB-4 (External Ecosystem / AI Layer):** Untrusted for raw secret access. Communicates strictly through `shield_core/contracts.py` (`ScopedEcosystemAdapter` + `RedactedCredentialView`).

---

## Threat Analysis (STRIDE Matrix)

| Threat Scenario | STRIDE | 1. Attacker Access | 2. Attacker Goal | 3. Current Defense | 4. Impact If Defense Fails | 5. Failure Detection |
|---|---|---|---|---|---|---|
| **1. Stolen / Lost Device (Locked)** | I, E | Raw disk & `shield_vault.db` | Offline crack master password & read credentials | Argon2id (64 MiB), AES-256-GCM per-record DEKs, zero plaintext in DB/logs | Full vault disclosure if master password is weak | Revoke device on clean machine; audit logs on synced devices |
| **2. Malicious Local Process (Unprivileged)** | I, T | File read/write, clipboard monitoring | Steal copied secrets or tamper with DB/code | Auto-clear clipboard (20s), owner-only permissions (`0o600` POSIX), anti-rollback manifest, `app_manifest.json` | Copied secret captured during 20s window | Integrity check on startup (`app_integrity.py`) & unlock (`VaultIntegrityError`) |
| **3. Active Malware / Keylogger / Kernel Rootkit** | S, I, E | Live keystrokes, screen, process RAM | Capture master password & live decrypted secrets | **Out of scope for pure user-space Python.** Mitigated partially by MFA (TOTP on separate device) and auto-lock | Full compromise of live session while unlocked | Unusual login/device audit alerts on secondary machines |
| **4. Memory Extraction (RAM Dump)** | I | Process memory dump while unlocked | Extract `VMK` or decrypted `VaultEntry` objects | Auto-lock inactivity timer, RAM-only keys cleared on lock (**Honest limitation:** Python GC/immutable `str` cannot guarantee immediate zeroization — primary reason for future Rust core) | Exposure of unlocked session secrets | OS-level EDR / anomaly monitoring |
| **5. Database Manipulation / Rollback** | T, R | Direct SQLite write access | Silently delete/inject/rollback records or erase audit trail | Per-record AES-GCM + AAD, VMK-encrypted `record_digests` manifest, Ed25519-signed SHA-256 audit chain | Forced rollback to older valid DB+secrets snapshot pair | `VaultIntegrityError` on unlock; Ed25519 signature failure on `verify_audit_log_integrity()` |
| **6. Malicious Sync Provider (e.g., compromised cloud)** | I, T, D | Read/modify/corrupt synced `.shield.enc` | Read credentials, inject rogue entries, or cause DoS | Client-side Argon2id + AES-256-GCM, SHA-256 checksum, Ed25519 signature, KDF upper-bound DoS clamping | Sync refused; availability disruption (resolved via local rolling snapshots) | Checksum/signature failure logged in Audit Log |
| **7. Phishing & Credential Theft** | S, I | Tricks user into visiting lookalike domain | Steal site credentials | Punycode (`xn--`) & `http://` warnings, known-breach site advisories, per-entry 2FA/Passkey encouragement | Single-account compromise (contained by reuse protection) | Reuse protection prevents lateral compromise; Health Audit flags risky domains |
| **8. Compromised Recovery Mechanism** | E, I | Access to offline Recovery Kit | Unwrap VMK and reset master password | Zero-reset design (no email/SMS reset), 200-bit offline Recovery Key, rate-limited recovery attempts, revoked-device check | Full vault access if attacker has BOTH DB file AND offline Recovery Kit | Critical `vault_recovered` Ed25519 audit event logged |
| **9. Supply-Chain Attack (Dependencies)** | T, E | Compromised PyPI package (`cryptography`, `qrcode`) | Exfiltrate keys or weaken crypto | Minimal 2-package dependency surface, local Patch Posture baseline checks (`governance_ops.py`) | Arbitrary code execution inside app process | Pinning/hash verification + future release signing (Phase 5/6) |
| **10. Malicious / Compromised App Updates** | T, S | Modified `.py` source files or injected module in `shield_core/` | Backdoor unlock flow | Startup **Application Integrity Verification** (`app_manifest.json` SHA-256 + unexpected-file detection) | Backdoor runs if attacker also replaces unsigned manifest (Phase 5: external release key signing) | Loud integrity banner on Lock Screen & Dashboard |

---

## Explicit Non-Goals & Honest Boundaries
- **User-space Python cannot defeat an active kernel rootkit or OS-level keylogger.** Endpoint hygiene (OS patches, full-disk encryption, separate authenticator device) remains essential.
- **Clipboard clearing reduces exposure window**, but cannot prevent another process from reading the clipboard during the active window.
- **Deterministic core independence:** Any future AI assistant interacts *only* through `ScopedEcosystemAdapter` using `RedactedCredentialView` — never raw credentials or keys.
