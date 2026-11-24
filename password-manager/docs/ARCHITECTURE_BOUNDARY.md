# Modular Architecture & Hybrid Rust/Python Integration Boundary

The password vault is designed as an **independently trustworthy, standalone module** within the larger P.U.L.S.E. ecosystem, with clean internal boundaries so the security-critical core can migrate to **Rust (`PyO3` or local IPC)** without rewriting the Python application layer.

## Layered Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Python Application Layer (Rapid UI, Intelligence & Automation)      │
│  app.py • dialogs.py • security_audit.py • governance_ops.py         │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Narrow Versioned Contract (v1.0.0)
                                │ shield_core/contracts.py
                                │ (SecurityEngineProtocol + PermissionScope)
┌───────────────────────────────▼──────────────────────────────────────┐
│  Security Core Boundary (Current: Python + Rust-backed cryptography  │
│                          Target:  Independent Rust crate via PyO3)   │
│  • Key Management  (Argon2id, AES-256-GCM, VMK/DEK, zeroize)         │
│  • Identity & Auth (Rate limits, TOTP anti-replay, device trust)     │
│  • Integrity       (Per-record manifest, Ed25519 audit signatures)   │
│  • Storage         (SQLite WAL, rolling snapshots, signed backups)   │
└──────────────────────────────────────────────────────────────────────┘
                                ▲
                                │ Strictly Redacted Read-Only Scopes
                                │ (ScopedEcosystemAdapter -> RedactedCredentialView)
┌───────────────────────────────┴──────────────────────────────────────┐
│  Future P.U.L.S.E. Ecosystem / AI Analyst (Zero Secret Access)       │
│  Receives policy scores, risk summaries & redacted metadata ONLY.    │
└──────────────────────────────────────────────────────────────────────┘
```

## Migration Path to an Independent Rust Security Core

1. **Crate Independence:** Build `shield_engine` as a standalone Rust library (`Cargo.toml`) with zero Python dependency:
   - Crates: `argon2`, `aes-gcm`, `x25519-dalek`, `ed25519-dalek`, `zeroize` (explicit secret zeroization on drop), `rusqlite`.
2. **Thin Binding Layer (`shield_engine_py`):** Expose `SecurityEngineProtocol` methods via **PyO3**, keeping `VMK`, `DEKs`, and `Ed25519` private keys strictly inside Rust-owned structs (`Zeroizing<[u8; 32]>`).
3. **Zero UI / Workflow Rewrite:** Because `app.py`, `security_audit.py`, `governance_ops.py`, and `purple_team_suite.py` interact through the clean boundary contract in [contracts.py](file:///C:/Users/alfie/.gemini/antigravity/scratch/password-manager/shield_core/contracts.py), the Rust core can drop in behind the exact same verification & Purple-Team test suite.

## Permission Scopes (`PermissionScope`)
- `vault:status` — locked/unlocked & recovery-kit readiness only.
- `credential:metadata:read` — returns `RedactedCredentialView` (no passwords, no TOTP secrets, no notes).
- `credential:secret:read` — single-record authorized read (never bulk dump to external callers).
- `security:audit:read` — 5-Pillar compliance, policy violations, and patch posture.
- `audit:log:read` — redacted hash-chained Ed25519 audit events.
