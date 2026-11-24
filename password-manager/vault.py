"""Compatibility facade re-exporting the P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T. engine."""

from shield_core.identity_access import DeviceRevokedError, RateLimitError, TrustedDevice
from shield_core.password_gen import evaluate_strength, generate_password
from shield_core.vault_engine import (
    CATEGORIES,
    ENTRY_TYPES,
    InvalidMFACodeError,
    InvalidPasswordError,
    ShieldVault,
    VaultEntry,
    VaultError,
    VaultFormatError,
    VaultIntegrityError,
    VaultLockedError,
)

# Backwards-compatible alias
PasswordVault = ShieldVault

__all__ = [
    "CATEGORIES",
    "ENTRY_TYPES",
    "DeviceRevokedError",
    "InvalidMFACodeError",
    "InvalidPasswordError",
    "PasswordVault",
    "RateLimitError",
    "ShieldVault",
    "TrustedDevice",
    "VaultEntry",
    "VaultError",
    "VaultFormatError",
    "VaultLockedError",
    "evaluate_strength",
    "generate_password",
]
