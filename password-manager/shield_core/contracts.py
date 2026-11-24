"""Versioned Internal Security Boundary Contracts (Rust/PyO3 & Ecosystem Integration Ready).

Design principles:
- External ecosystem components (such as P.U.L.S.E. intelligence or future UIs) MUST NOT
  access raw cryptographic keys, SQLite connections, or bulk decrypted secrets directly.
- Every cross-boundary request specifies an explicit `PermissionScope`.
- `RedactedCredentialView` structurally omits passwords, TOTP secrets, notes, and custom
  field values so analytics/AI assistants can evaluate posture without ever seeing secrets.
- `SecurityEngineProtocol` defines the narrow interface that an independent Rust library
  (exposed via PyO3 or local IPC) can implement cleanly as a drop-in security core.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from shield_core.vault_engine import VaultEntry

CONTRACT_VERSION = "1.0.0"


class PermissionScope(str, Enum):
    VAULT_STATUS = "vault:status"
    CREDENTIAL_METADATA_READ = "credential:metadata:read"  # Redacted (no secrets)
    CREDENTIAL_SECRET_READ = "credential:secret:read"  # Single-record authorized access only
    CREDENTIAL_WRITE = "credential:write"
    SECURITY_AUDIT_READ = "security:audit:read"
    GOVERNANCE_WRITE = "governance:write"
    RECOVERY_EXECUTE = "recovery:execute"
    AUDIT_LOG_READ = "audit:log:read"


class PermissionDeniedError(PermissionError):
    """Raised when an ecosystem caller requests an operation outside its granted scopes."""


@dataclass(frozen=True)
class RedactedCredentialView:
    """Zero-secret projection safe to share with risk/policy/AI analysis components."""

    id: str
    entry_type: str
    category: str
    has_password: bool
    password_length: int
    has_totp: bool
    passkey_enabled: bool
    url_scheme: str
    url_domain: str
    favorite: bool
    tags: tuple[str, ...]
    created_at: str
    password_updated_at: str

    @classmethod
    def from_entry(cls, entry: VaultEntry) -> "RedactedCredentialView":
        from urllib.parse import urlparse

        raw_url = (entry.url or "").strip()
        scheme = ""
        domain = ""
        if raw_url:
            norm = raw_url if "://" in raw_url else f"https://{raw_url}"
            parsed = urlparse(norm)
            scheme = parsed.scheme.lower()
            domain = (parsed.hostname or "").lower()
        return cls(
            id=entry.id,
            entry_type=entry.entry_type,
            category=entry.category,
            has_password=bool(entry.password),
            password_length=len(entry.password or ""),
            has_totp=bool(entry.totp_secret),
            passkey_enabled=bool(entry.passkey_enabled),
            url_scheme=scheme,
            url_domain=domain,
            favorite=bool(entry.favorite),
            tags=tuple(entry.tags),
            created_at=entry.created_at,
            password_updated_at=entry.password_updated_at,
        )


@runtime_checkable
class SecurityEngineProtocol(Protocol):
    """Narrow boundary contract for a Python or Rust (PyO3) security core implementation."""

    @property
    def is_unlocked(self) -> bool: ...

    @property
    def mfa_enabled(self) -> bool: ...

    @property
    def has_recovery_kit(self) -> bool: ...

    def unlock(self, master_password: str) -> bool: ...

    def complete_mfa(self, code: str) -> bool: ...

    def lock(self) -> None: ...

    def verify_vault_integrity(self) -> tuple[bool, str]: ...

    def verify_audit_log_integrity(self) -> tuple[bool, str]: ...

    def evaluate_five_pillars(self) -> list[dict[str, str]]: ...


class ScopedEcosystemAdapter:
    """Permission-enforcing facade mediating between external P.U.L.S.E. components and the vault.

    Guarantees deterministic permission checks: external/AI callers never receive raw keys or bulk passwords.
    """

    def __init__(self, engine: Any, granted_scopes: set[PermissionScope]) -> None:
        self._engine = engine
        self._scopes = frozenset(granted_scopes)

    def _require(self, scope: PermissionScope) -> None:
        if scope not in self._scopes:
            raise PermissionDeniedError(f"Caller lacks required permission scope: {scope.value}")

    def get_vault_status(self) -> dict[str, Any]:
        self._require(PermissionScope.VAULT_STATUS)
        return {
            "contract_version": CONTRACT_VERSION,
            "is_unlocked": bool(self._engine.is_unlocked),
            "has_recovery_kit": bool(self._engine.has_recovery_kit),
        }

    def list_redacted_credentials(self) -> list[RedactedCredentialView]:
        """Return strictly redacted credential metadata (zero passwords, zero TOTP secrets)."""
        self._require(PermissionScope.CREDENTIAL_METADATA_READ)
        return [RedactedCredentialView.from_entry(e) for e in self._engine.list_entries()]

    def get_security_posture(self) -> dict[str, Any]:
        """Return redacted 5-Pillar + Policy Compliance + Patch Posture summary."""
        self._require(PermissionScope.SECURITY_AUDIT_READ)
        pol_score, pol_checks = self._engine.evaluate_policy_compliance()
        return {
            "contract_version": CONTRACT_VERSION,
            "five_pillars": self._engine.evaluate_five_pillars(),
            "policy_compliance_percent": pol_score,
            "policy_violations": [
                {"id": c.policy_id, "name": c.name, "status": c.status, "violations": c.violations}
                for c in pol_checks
                if c.status != "PASS"
            ],
            "patch_posture": [
                {"component": p.component, "installed": p.installed_version, "status": p.status}
                for p in self._engine.get_patch_posture()
            ],
        }
