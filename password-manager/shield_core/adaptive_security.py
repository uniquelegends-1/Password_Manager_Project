"""Adaptive Security Policy Engine (Deterministic, AI-Independent).

Enforces risk-proportional friction:
- Low-sensitivity reads (viewing username) -> Normal access
- Medium sensitivity (revealing password on high-risk/Finance entries) -> Optional re-auth + temporary auto-hide
- High sensitivity (exporting vault, revoking devices, changing MFA/master password, generating recovery kit)
  -> Mandatory strong re-authentication (Master Password + MFA if enabled)
- Elevated threat state (recent failed login attempts) -> Automatically tightens verification requirements
"""

from __future__ import annotations

from dataclasses import dataclass

SENSITIVE_CATEGORIES = frozenset({"Finance", "Email", "Work"})


@dataclass
class AdaptivePolicyConfig:
    require_reauth_for_sensitive_reveal: bool = False
    require_reauth_for_exports: bool = True
    require_reauth_for_security_changes: bool = True
    require_reauth_for_device_management: bool = True
    temp_reveal_seconds: int = 15
    clipboard_clear_seconds: int = 20
    auto_lock_seconds: int = 300

    def to_dict(self) -> dict[str, object]:
        return {
            "require_reauth_for_sensitive_reveal": self.require_reauth_for_sensitive_reveal,
            "require_reauth_for_exports": self.require_reauth_for_exports,
            "require_reauth_for_security_changes": self.require_reauth_for_security_changes,
            "require_reauth_for_device_management": self.require_reauth_for_device_management,
            "temp_reveal_seconds": self.temp_reveal_seconds,
            "clipboard_clear_seconds": self.clipboard_clear_seconds,
            "auto_lock_seconds": self.auto_lock_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> "AdaptivePolicyConfig":
        if not isinstance(data, dict):
            return cls()
        return cls(
            require_reauth_for_sensitive_reveal=bool(data.get("require_reauth_for_sensitive_reveal", False)),
            require_reauth_for_exports=bool(data.get("require_reauth_for_exports", True)),
            require_reauth_for_security_changes=bool(data.get("require_reauth_for_security_changes", True)),
            require_reauth_for_device_management=bool(data.get("require_reauth_for_device_management", True)),
            temp_reveal_seconds=max(5, min(60, int(data.get("temp_reveal_seconds", 15)))),
            clipboard_clear_seconds=max(5, min(120, int(data.get("clipboard_clear_seconds", 20)))),
            auto_lock_seconds=max(60, min(3600, int(data.get("auto_lock_seconds", 300)))),
        )


@dataclass(frozen=True)
class SecurityRequirement:
    action: str
    level: str  # "normal" | "reauth" | "strong"
    require_master_password: bool
    require_mfa: bool
    reason: str


def evaluate_action(
    action: str,
    config: AdaptivePolicyConfig,
    *,
    entry_category: str = "General",
    mfa_enabled: bool = False,
    recent_failed_logins: int = 0,
) -> SecurityRequirement:
    """Deterministically evaluate the verification level required for an action."""
    elevated_threat = recent_failed_logins >= 2

    if action == "view_username":
        return SecurityRequirement(action, "normal", False, False, "Standard credential lookup.")

    if action == "reveal_password":
        sensitive = entry_category in SENSITIVE_CATEGORIES
        if (config.require_reauth_for_sensitive_reveal and sensitive) or elevated_threat:
            reason = (
                "Elevated security: recent failed logins detected."
                if elevated_threat
                else f"Adaptive policy requires re-authentication before revealing {entry_category} passwords."
            )
            return SecurityRequirement(action, "reauth", True, False, reason)
        return SecurityRequirement(
            action,
            "normal",
            False,
            False,
            f"Temporary reveal (auto-hides in {config.temp_reveal_seconds}s).",
        )

    if action in ("export_vault", "export_plaintext_json", "export_google_csv"):
        if config.require_reauth_for_exports or elevated_threat:
            return SecurityRequirement(
                action,
                "strong",
                True,
                mfa_enabled,
                "Exporting vault credentials requires strong authentication.",
            )
        return SecurityRequirement(action, "normal", False, False, "Export permitted by policy.")

    if action in ("manage_devices", "revoke_device", "add_device"):
        if config.require_reauth_for_device_management or elevated_threat:
            return SecurityRequirement(
                action,
                "strong",
                True,
                mfa_enabled,
                "Modifying trusted devices requires strong authentication.",
            )
        return SecurityRequirement(action, "normal", False, False, "Device change permitted.")

    if action in ("change_master_password", "change_mfa", "generate_recovery_kit", "change_security_settings"):
        if config.require_reauth_for_security_changes or elevated_threat:
            return SecurityRequirement(
                action,
                "strong",
                True,
                mfa_enabled,
                "Changing core security controls requires strong authentication.",
            )
        return SecurityRequirement(action, "normal", False, False, "Security setting change permitted.")

    # Default fail-safe for unknown sensitive actions
    return SecurityRequirement(
        action,
        "strong",
        True,
        mfa_enabled,
        "Unclassified sensitive operation defaults to strong authentication.",
    )
