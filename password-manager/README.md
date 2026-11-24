# P.U.L.S.E. Password Vault — S.H.I.E.L.D. / V.A.U.L.T.

A Python-first, local-first, zero-trust desktop password vault and digital identity security center. Its deterministic security core is completely independent of any AI layer — enforcing authentication, encryption, adaptive security, and audit integrity locally.

## Architecture (`shield_core/`)

| Internal Engine | Module | Key Capabilities |
|---|---|---|
| **Key Management** | `shield_core/key_management.py` | **Argon2id** KDF (64 MiB), **AES-256-GCM**, memory-only Vault Master Key (VMK), **per-record 256-bit DEKs**, zero-reset Emergency Recovery Kit key wrapping |
| **Credential Engine** | `shield_core/vault_engine.py` | **SQLite** WAL database, 8 credential types (Website, App, Email, Secure Note, Recovery Codes, API Key, Wi-Fi, Software Licence), custom fields, categories, tags, favorites |
| **Identity & Access** | `shield_core/identity_access.py` | Progressive brute-force rate limiting, failed-login monitoring, trusted device registry & device revocation |
| **MFA Management** | `shield_core/mfa.py` | RFC 6238 TOTP (Google/Microsoft Authenticator, Aegis, 2FAS), **anti-replay time-step protection**, QR canvas rendering, one-time recovery codes, per-entry 2FA & Passkey tracking |
| **Adaptive Security** | `shield_core/adaptive_security.py` | Risk-proportional verification (normal lookup -> temporary reveal -> strong re-auth for exports, device changes, and security settings) |
| **Password Generator** | `shield_core/password_gen.py` | Python `secrets` CSPRNG, letters/numbers/special/extended/custom chars, exclude ambiguous, Diceware passphrases, **site-specific policies**, entropy & crack-time scoring |
| **Security Intelligence** | `shield_core/security_audit.py` | Vault Health Score (0–100), prioritized risk ranking with clear explanations, real-time reuse protection, known breach advisories, opt-in **HIBP k-Anonymity** & **live TLS/header scanner** |
| **Recovery & Portability** | `shield_core/recovery_backup.py` | Zero-reset recovery, versioned encrypted backups (`.shield.enc`), **backup integrity / restore testing**, encrypted/plaintext JSON portability |
| **E2EE & Google Vault** | `shield_core/e2ee.py`, `shield_core/google_sync.py` | Zero-knowledge E2EE sync merge, X25519 + HKDF + AES-256-GCM entry sharing, consent-gated Google Password Manager CSV import/export (with secure shred) & Google Drive E2EE sync |
| **Tamper-Evident Audit** | `shield_core/audit_log.py` | **Ed25519-signed, SHA-256 hash-chained** SQLite security event log with strict secret redaction, chain verification, and verifiable signed JSON proof export |
| **Governance, Risk & IR** | `shield_core/governance_ops.py` | Enforceable **Security Policies** (`min_length`, `warn`/`block` reuse, HTTPS, MFA, backup cadence), **Risk Register** (Likelihood × Impact), **Incident Response** playbooks + **Emergency Containment**, **Patch Posture** scanner, and live **Disaster Recovery Readiness Drills** |

## 5 Pillars of Cybersecurity Compliance

| Pillar | Concrete Mechanisms in S.H.I.E.L.D. / V.A.U.L.T. |
|---|---|
| **Confidentiality** | Argon2id (64 MiB), AES-256-GCM, RAM-only VMK, independent 256-bit DEK per record, zero plaintext in SQLite or audit logs, auto-clearing clipboard, temporary password reveal, inactivity auto-lock |
| **Integrity** | AES-256-GCM 128-bit auth tags + AAD, VMK-authenticated **anti-deletion/anti-rollback record digest manifest**, SHA-256 backup checksums, atomic `fsync` + `os.replace` writes, SQLite `PRAGMA integrity_check` |
| **Availability** | Offline-first local SQLite WAL storage, Zero-Reset Emergency Recovery Kit, versioned encrypted backups (`.shield.enc`), automatic **rolling SQLite snapshots** before critical changes, non-destructive restore integrity tests |
| **Authenticity** | Argon2id master verification, RFC 6238 TOTP MFA with anti-replay & rate limiting, trusted device registry & revocation, adaptive re-authentication, **Ed25519 digital signatures** verifying source authenticity of E2EE shares & backups |
| **Non-Repudiation** | **Ed25519-signed, SHA-256 hash-chained** audit log binding `(vault_id, device_id, event_hash)` per action, plus exportable verifiable JSON audit proofs |

## Running as a Desktop App (No PowerShell Required)

- **Windows Start Menu:** Press the **Windows key** and type **`S.H.I.E.L.D. Vault`** (right-click to **Pin to taskbar**).
- **Desktop:** Double-click **`S.H.I.E.L.D. Vault`** on your Desktop (or inside the project folder).
- Launches directly via `pythonw.exe` with a custom shield icon and **no PowerShell/console window**.
- To recreate shortcuts anytime: `python install_desktop_app.py`.

## Verification, Integrity & Architecture Documentation
- **Application Integrity Verification:** `shield_core/app_integrity.py` verifies all 19 critical source files against `app_manifest.json` on every startup.
- **Isolated Purple-Team Adversarial Testing:** Run `python purple_team_suite.py` to execute 8 hostile attack simulations in a synthetic sandbox and generate `docs/PURPLE_TEAM_REPORT.md`.
- **Threat Model & Rust/Python Boundary:** See `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE_BOUNDARY.md`, and `shield_core/contracts.py`.

## Running the Unit Test Suite
```powershell
python -m unittest discover -v
```
