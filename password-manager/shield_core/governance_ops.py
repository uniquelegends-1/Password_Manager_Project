"""Governance, Risk, Incident Response, Patch Posture & Recovery Workflows for S.H.I.E.L.D. / V.A.U.L.T.

All controls are deterministic, local-first, zero-telemetry, and independent of any AI layer.
"""

from __future__ import annotations

import platform
import sqlite3
import ssl
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from typing import TYPE_CHECKING, Any

from shield_core.security_audit import audit_vault

if TYPE_CHECKING:
    from shield_core.vault_engine import VaultEntry


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ====================================================================== #
# 1. Enforceable Security Policies
# ====================================================================== #


@dataclass
class SecurityPolicyConfig:
    min_password_length: int = 12
    max_password_age_days: int = 180
    reuse_policy: str = "warn"  # "warn" | "block"
    require_https_urls: bool = True
    require_mfa_for_high_value: bool = True
    require_vault_mfa: bool = True
    require_recovery_kit: bool = True
    max_days_between_backups: int = 30

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SecurityPolicyConfig":
        if not isinstance(data, dict):
            return cls()
        reuse = str(data.get("reuse_policy", "warn")).lower()
        if reuse not in ("warn", "block"):
            reuse = "warn"
        return cls(
            min_password_length=max(8, min(32, int(data.get("min_password_length", 12)))),
            max_password_age_days=max(30, min(730, int(data.get("max_password_age_days", 180)))),
            reuse_policy=reuse,
            require_https_urls=bool(data.get("require_https_urls", True)),
            require_mfa_for_high_value=bool(data.get("require_mfa_for_high_value", True)),
            require_vault_mfa=bool(data.get("require_vault_mfa", True)),
            require_recovery_kit=bool(data.get("require_recovery_kit", True)),
            max_days_between_backups=max(1, min(365, int(data.get("max_days_between_backups", 30)))),
        )


@dataclass
class PolicyCheckResult:
    policy_id: str
    name: str
    status: str  # "PASS" | "WARN" | "FAIL"
    violations: int
    detail: str


def evaluate_policy_compliance(
    entries: list[VaultEntry],
    policy: SecurityPolicyConfig,
    *,
    vault_mfa_enabled: bool,
    has_recovery_kit: bool,
    last_backup_at: str = "",
) -> tuple[int, list[PolicyCheckResult]]:
    """Evaluate all configured security policies. Returns (compliance_percent, check_results)."""
    checks: list[PolicyCheckResult] = []
    report = audit_vault(entries, stale_days=policy.max_password_age_days)

    # 1. Minimum password length
    short = [e for e in entries if e.password and len(e.password) < policy.min_password_length]
    checks.append(
        PolicyCheckResult(
            "POL-LEN",
            f"Minimum Password Length (>= {policy.min_password_length} chars)",
            "PASS" if not short else "FAIL",
            len(short),
            "All credentials meet minimum length." if not short else f"{len(short)} credential(s) are shorter than {policy.min_password_length} chars.",
        )
    )

    # 2. Password reuse prohibition
    checks.append(
        PolicyCheckResult(
            "POL-REUSE",
            f"Unique Passwords (Mode: {policy.reuse_policy.upper()})",
            "PASS" if report.reused_count == 0 else "FAIL",
            report.reused_count,
            "No password reuse detected." if report.reused_count == 0 else f"{report.reused_count} credential(s) share duplicated passwords.",
        )
    )

    # 3. Password rotation age
    checks.append(
        PolicyCheckResult(
            "POL-AGE",
            f"Password Rotation (<= {policy.max_password_age_days} days)",
            "PASS" if report.stale_count == 0 else "WARN",
            report.stale_count,
            "All passwords within rotation window." if report.stale_count == 0 else f"{report.stale_count} password(s) exceed {policy.max_password_age_days} days.",
        )
    )

    # 4. HTTPS enforcement
    if policy.require_https_urls:
        http_entries = [e for e in entries if e.url.strip().lower().startswith("http://")]
        checks.append(
            PolicyCheckResult(
                "POL-HTTPS",
                "HTTPS Transport Only (No http://)",
                "PASS" if not http_entries else "FAIL",
                len(http_entries),
                "All saved URLs use HTTPS." if not http_entries else f"{len(http_entries)} URL(s) still use unencrypted http://.",
            )
        )

    # 5. MFA on high-value accounts
    if policy.require_mfa_for_high_value:
        hv_missing = [
            e
            for e in entries
            if e.category in ("Finance", "Email", "Work")
            and not e.totp_secret
            and not e.passkey_enabled
        ]
        checks.append(
            PolicyCheckResult(
                "POL-HV-MFA",
                "2FA / Passkey on Finance, Email & Work Accounts",
                "PASS" if not hv_missing else "WARN",
                len(hv_missing),
                "All high-value accounts have 2FA/Passkey." if not hv_missing else f"{len(hv_missing)} high-value account(s) lack 2FA/Passkey.",
            )
        )

    # 6. Vault-level MFA
    if policy.require_vault_mfa:
        checks.append(
            PolicyCheckResult(
                "POL-VAULT-MFA",
                "Vault Unlock Multi-Factor Authentication",
                "PASS" if vault_mfa_enabled else "FAIL",
                0 if vault_mfa_enabled else 1,
                "Vault TOTP MFA with anti-replay is active." if vault_mfa_enabled else "Vault MFA is disabled — enable in Identity & Devices.",
            )
        )

    # 7. Zero-Reset Emergency Recovery Kit
    if policy.require_recovery_kit:
        checks.append(
            PolicyCheckResult(
                "POL-RECOVERY",
                "Emergency Recovery Kit Configured",
                "PASS" if has_recovery_kit else "FAIL",
                0 if has_recovery_kit else 1,
                "Emergency Recovery Kit is active." if has_recovery_kit else "No Emergency Recovery Kit — risk of permanent lockout.",
            )
        )

    # 8. Backup freshness
    bak_ok = False
    bak_detail = "No encrypted backup has been created yet."
    if last_backup_at:
        try:
            dt = datetime.strptime(last_backup_at, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
            days = (datetime.now(timezone.utc) - dt).days
            bak_ok = days <= policy.max_days_between_backups
            bak_detail = f"Last encrypted backup was {days} day(s) ago (limit: {policy.max_days_between_backups}d)."
        except ValueError:
            bak_ok = True
            bak_detail = f"Last backup recorded: {last_backup_at}."
    checks.append(
        PolicyCheckResult(
            "POL-BACKUP",
            f"Encrypted Backup Cadence (<= {policy.max_days_between_backups} days)",
            "PASS" if bak_ok else "WARN",
            0 if bak_ok else 1,
            bak_detail,
        )
    )

    passed = sum(1 for c in checks if c.status == "PASS")
    score_pct = int(round((passed / len(checks)) * 100)) if checks else 100
    return score_pct, checks


# ====================================================================== #
# 2. Risk Management & Risk Register (Likelihood x Impact Matrix)
# ====================================================================== #


@dataclass
class RiskRecord:
    id: str
    title: str
    category: str  # "Credential" | "Identity" | "Availability" | "Platform/Patch" | "Integrity"
    likelihood: int  # 1..5
    impact: int  # 1..5
    status: str = "Open"  # "Open" | "Mitigating" | "Accepted" | "Closed"
    mitigation: str = ""
    owner_note: str = ""
    auto_detected: bool = False
    updated_at: str = ""

    @property
    def score(self) -> int:
        return max(1, min(5, self.likelihood)) * max(1, min(5, self.impact))

    @property
    def rating(self) -> str:
        s = self.score
        if s >= 16:
            return "Critical"
        if s >= 10:
            return "High"
        if s >= 5:
            return "Medium"
        return "Low"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RiskRecord":
        return cls(
            id=str(data.get("id") or f"RSK-{uuid.uuid4().hex[:6].upper()}"),
            title=str(data.get("title", "Unnamed Risk")),
            category=str(data.get("category", "Credential")),
            likelihood=max(1, min(5, int(data.get("likelihood", 3)))),
            impact=max(1, min(5, int(data.get("impact", 3)))),
            status=str(data.get("status", "Open")),
            mitigation=str(data.get("mitigation", "")),
            owner_note=str(data.get("owner_note", "")),
            auto_detected=bool(data.get("auto_detected", False)),
            updated_at=str(data.get("updated_at", _utc_now())),
        )


def synthesize_auto_risks(
    entries: list[VaultEntry],
    policy_checks: list[PolicyCheckResult],
    patch_items: list["PatchCheckItem"],
    *,
    chain_ok: bool,
    failed_logins: int,
) -> list[RiskRecord]:
    """Deterministically generate live risk register entries from current security posture."""
    now = _utc_now()
    risks: list[RiskRecord] = []

    if not chain_ok:
        risks.append(
            RiskRecord(
                id="AUTO-INTEGRITY",
                title="Audit Log Hash-Chain / Ed25519 Signature Mismatch",
                category="Integrity",
                likelihood=5,
                impact=5,
                status="Open",
                mitigation="Trigger Tampering IR Playbook, inspect snapshots, rotate master password & keys.",
                auto_detected=True,
                updated_at=now,
            )
        )

    if failed_logins >= 3:
        risks.append(
            RiskRecord(
                id="AUTO-BRUTEFORCE",
                title=f"Elevated Failed Authentication Attempts ({failed_logins} recorded)",
                category="Identity",
                likelihood=4,
                impact=4,
                status="Open",
                mitigation="Review Audit Log & Trusted Devices; revoke unknown devices and ensure MFA is active.",
                auto_detected=True,
                updated_at=now,
            )
        )

    check_map = {c.policy_id: c for c in policy_checks}
    if check_map.get("POL-REUSE") and check_map["POL-REUSE"].status != "PASS":
        risks.append(
            RiskRecord(
                id="AUTO-REUSE",
                title=f"Credential Stuffing Exposure ({check_map['POL-REUSE'].violations} reused passwords)",
                category="Credential",
                likelihood=4,
                impact=4,
                status="Open",
                mitigation="Replace duplicated passwords with unique generated secrets via Health & Risk Audit.",
                auto_detected=True,
                updated_at=now,
            )
        )

    if check_map.get("POL-VAULT-MFA") and check_map["POL-VAULT-MFA"].status != "PASS":
        risks.append(
            RiskRecord(
                id="AUTO-NOMFA",
                title="Single-Factor Vault Authentication (Vault MFA Disabled)",
                category="Identity",
                likelihood=3,
                impact=5,
                status="Open",
                mitigation="Enable TOTP MFA with anti-replay in Identity & Devices.",
                auto_detected=True,
                updated_at=now,
            )
        )

    if check_map.get("POL-RECOVERY") and check_map["POL-RECOVERY"].status != "PASS":
        risks.append(
            RiskRecord(
                id="AUTO-NORECOVERY",
                title="Permanent Lockout Risk (No Emergency Recovery Kit)",
                category="Availability",
                likelihood=2,
                impact=5,
                status="Open",
                mitigation="Generate an offline Emergency Recovery Kit in Backup & Recovery.",
                auto_detected=True,
                updated_at=now,
            )
        )

    if check_map.get("POL-BACKUP") and check_map["POL-BACKUP"].status != "PASS":
        risks.append(
            RiskRecord(
                id="AUTO-NOBACKUP",
                title="Backup Redundancy Gap (No Recent Encrypted Backup)",
                category="Availability",
                likelihood=3,
                impact=4,
                status="Open",
                mitigation="Create a versioned Ed25519-signed encrypted backup and verify restore integrity.",
                auto_detected=True,
                updated_at=now,
            )
        )

    outdated_patches = [p for p in patch_items if p.status == "OUTDATED"]
    if outdated_patches:
        names = ", ".join(p.component for p in outdated_patches)
        risks.append(
            RiskRecord(
                id="AUTO-PATCH",
                title=f"Outdated Security Component(s): {names}",
                category="Platform/Patch",
                likelihood=3,
                impact=4,
                status="Open",
                mitigation="Update flagged runtime/dependencies and re-run Patch Posture Check.",
                auto_detected=True,
                updated_at=now,
            )
        )

    risks.sort(key=lambda r: (-r.score, r.title))
    return risks


# ====================================================================== #
# 3. Incident Response (IR) Playbooks & Case Management
# ====================================================================== #


IR_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "Suspected Master Password Exposure": {
        "severity": "critical",
        "steps": [
            "[Contain] Run Emergency Containment / Lock Vault and revoke untrusted devices.",
            "[Contain] Create a rolling SQLite snapshot for forensic preservation.",
            "[Eradicate] Rotate the Master Password immediately (Argon2id VMK re-wrap).",
            "[Eradicate] Enable or verify Vault TOTP MFA and rotate Emergency Recovery Kit.",
            "[Recover] Export a fresh Ed25519-signed encrypted backup and verify integrity.",
            "[Post-Incident] Export Signed Audit Proof and document root cause.",
        ],
    },
    "Account / Website Data Breach": {
        "severity": "high",
        "steps": [
            "[Detect] Run HIBP k-Anonymity Breach Check in Health & Risk Audit.",
            "[Contain] Identify all accounts sharing the breached password via Reuse Protection.",
            "[Eradicate] Generate unique 20+ char passwords for the breached account and any reused accounts.",
            "[Eradicate] Enable app-based TOTP 2FA or Passkey on affected websites.",
            "[Recover] Revoke active web sessions on the breached service.",
            "[Post-Incident] Re-run Health Audit to confirm risk score dropped.",
        ],
    },
    "Lost or Compromised Trusted Device": {
        "severity": "critical",
        "steps": [
            "[Contain] Open Identity & Devices -> Revoke the lost/compromised device immediately.",
            "[Contain] Trigger Emergency Containment if the device held an active sync file.",
            "[Eradicate] Rotate Master Password and rotate high-value Finance/Email/Work passwords.",
            "[Eradicate] Re-enroll MFA if the lost device was also your authenticator app (use recovery codes).",
            "[Recover] Perform an E2EE Sync push to overwrite synced vaults with fresh nonces.",
            "[Post-Incident] Export Signed Audit Proof and verify remaining trusted devices.",
        ],
    },
    "Database or Audit Log Tampering Detected": {
        "severity": "critical",
        "steps": [
            "[Detect] Run Full Vault Integrity Check & Verify Ed25519 Audit Chain.",
            "[Contain] Do NOT overwrite clean backups; preserve tampered DB copy for investigation.",
            "[Eradicate] Inspect system for malware/unauthorized local access.",
            "[Recover] Verify an untouched Rolling Snapshot or Ed25519-signed `.shield.enc` backup.",
            "[Recover] Restore from the verified backup onto a clean environment and rotate Master Password.",
            "[Post-Incident] Rotate Emergency Recovery Kit and re-verify all 5 Cybersecurity Pillars.",
        ],
    },
    "Phishing / Suspicious Login Attempt": {
        "severity": "high",
        "steps": [
            "[Detect] Check Security Audit Log for failed logins, rate-limit blocks, or new device IDs.",
            "[Contain] Enable Adaptive Re-Authentication for sensitive reveals in Identity & Devices.",
            "[Eradicate] Change password on any site where credentials may have been entered on a lookalike URL.",
            "[Recover] Verify URLs in Credential Library for http:// or Punycode (xn--) lookalikes.",
            "[Post-Incident] Close incident once account activity is confirmed clean.",
        ],
    },
}

IR_PHASES = ("Detect", "Contain", "Eradicate", "Recover", "Closed")


@dataclass
class IncidentCase:
    id: str
    title: str
    playbook: str
    severity: str
    phase: str = "Detect"
    steps: list[dict[str, Any]] = field(default_factory=list)  # [{"text": str, "done": bool}]
    notes: str = ""
    opened_at: str = ""
    closed_at: str = ""

    @classmethod
    def create_from_playbook(cls, playbook_name: str, custom_title: str = "") -> "IncidentCase":
        pb = IR_PLAYBOOKS.get(playbook_name)
        severity = pb["severity"] if pb else "high"
        raw_steps = pb["steps"] if pb else ["[Detect] Investigate alert.", "[Contain] Isolate impact.", "[Recover] Verify integrity."]
        return cls(
            id=f"INC-{uuid.uuid4().hex[:6].upper()}",
            title=(custom_title.strip() or playbook_name),
            playbook=playbook_name,
            severity=severity,
            phase="Detect",
            steps=[{"text": s, "done": False} for s in raw_steps],
            notes="",
            opened_at=_utc_now(),
            closed_at="",
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IncidentCase":
        raw_steps = data.get("steps", [])
        steps = [
            {"text": str(s.get("text", "")), "done": bool(s.get("done", False))}
            for s in raw_steps
            if isinstance(s, dict)
        ]
        return cls(
            id=str(data.get("id") or f"INC-{uuid.uuid4().hex[:6].upper()}"),
            title=str(data.get("title", "Security Incident")),
            playbook=str(data.get("playbook", "Custom")),
            severity=str(data.get("severity", "high")),
            phase=str(data.get("phase", "Detect")) if data.get("phase") in IR_PHASES else "Detect",
            steps=steps,
            notes=str(data.get("notes", "")),
            opened_at=str(data.get("opened_at", _utc_now())),
            closed_at=str(data.get("closed_at", "")),
        )


# ====================================================================== #
# 4. Patching & Dependency Security Posture Scanner
# ====================================================================== #


@dataclass
class PatchCheckItem:
    component: str
    installed_version: str
    minimum_secure: str
    status: str  # "UP TO DATE" | "REVIEW" | "OUTDATED"
    recommendation: str


def _parse_ver(ver_str: str) -> tuple[int, ...]:
    nums: list[int] = []
    for part in ver_str.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if digits:
            nums.append(int(digits))
        else:
            break
    return tuple(nums) if nums else (0,)


def check_patch_posture(kdf_memory_kib: int = 65536, kdf_iterations: int = 3) -> list[PatchCheckItem]:
    """Locally inspect Python, OpenSSL, SQLite, cryptography, qrcode, and KDF security baselines."""
    items: list[PatchCheckItem] = []

    # 1. Python runtime
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = (sys.version_info.major, sys.version_info.minor) >= (3, 11)
    items.append(
        PatchCheckItem(
            "Python Runtime",
            py_ver,
            ">= 3.11",
            "UP TO DATE" if py_ok else "OUTDATED",
            "Supported Python branch with security updates." if py_ok else "Upgrade Python to >= 3.11 to receive CVE patches.",
        )
    )

    # 2. OpenSSL / TLS backend
    ossl = ssl.OPENSSL_VERSION
    ossl_ver = ossl.split()[1] if len(ossl.split()) >= 2 else ossl
    ossl_ok = _parse_ver(ossl_ver) >= (3, 0, 0)
    items.append(
        PatchCheckItem(
            "OpenSSL / TLS Engine",
            ossl,
            "OpenSSL >= 3.0",
            "UP TO DATE" if ossl_ok else "OUTDATED",
            "Modern TLS 1.3 & OpenSSL 3.x crypto backend." if ossl_ok else "Upgrade Python/OpenSSL to OpenSSL 3.x.",
        )
    )

    # 3. SQLite3
    sq_ver = sqlite3.sqlite_version
    sq_ok = _parse_ver(sq_ver) >= (3, 38, 0)
    items.append(
        PatchCheckItem(
            "SQLite3 Storage Engine",
            sq_ver,
            ">= 3.38.0",
            "UP TO DATE" if sq_ok else "REVIEW",
            "Modern SQLite engine with WAL & integrity check." if sq_ok else "Consider updating Python for a newer SQLite build.",
        )
    )

    # 4. PyCA cryptography
    try:
        crypto_ver = importlib_metadata.version("cryptography")
        c_ok = _parse_ver(crypto_ver) >= (42, 0, 0)
        items.append(
            PatchCheckItem(
                "PyCA cryptography",
                crypto_ver,
                ">= 42.0.0",
                "UP TO DATE" if c_ok else "OUTDATED",
                "Rust-backed memory-safe AES-GCM, Argon2id, X25519 & Ed25519." if c_ok else "Run: python -m pip install --user --upgrade cryptography",
            )
        )
    except importlib_metadata.PackageNotFoundError:
        items.append(PatchCheckItem("PyCA cryptography", "Missing", ">= 42.0.0", "OUTDATED", "Install cryptography>=42.0.0."))

    # 5. qrcode
    try:
        qr_ver = importlib_metadata.version("qrcode")
        q_ok = _parse_ver(qr_ver) >= (7, 4, 0)
        items.append(
            PatchCheckItem(
                "qrcode (MFA QR)",
                qr_ver,
                ">= 7.4.0",
                "UP TO DATE" if q_ok else "REVIEW",
                "Current pure-Python QR matrix generator." if q_ok else "Run: python -m pip install --user --upgrade qrcode",
            )
        )
    except importlib_metadata.PackageNotFoundError:
        items.append(PatchCheckItem("qrcode (MFA QR)", "Not installed", ">= 7.4.0", "REVIEW", "Install qrcode>=7.4.2 for MFA QR codes."))

    # 6. Argon2id KDF Baseline
    kdf_ok = kdf_memory_kib >= 65536 and kdf_iterations >= 3
    items.append(
        PatchCheckItem(
            "Argon2id KDF Strength",
            f"{kdf_memory_kib // 1024} MiB / {kdf_iterations} iters",
            ">= 64 MiB / 3 iters",
            "UP TO DATE" if kdf_ok else "REVIEW",
            "Meets OWASP interactive Argon2id memory-hard standard." if kdf_ok else "Rotate master password under production defaults to upgrade KDF cost.",
        )
    )

    # 7. OS Info (informational)
    items.append(
        PatchCheckItem(
            "Host Operating System",
            platform.platform(),
            "OS Security Updates Enabled",
            "REVIEW",
            "Ensure OS security patches & full-disk encryption (BitLocker/FileVault) remain enabled.",
        )
    )
    return items


# ====================================================================== #
# 5. Guided Disaster Recovery (DR) Workflows
# ====================================================================== #


RECOVERY_WORKFLOWS: dict[str, list[str]] = {
    "Forgotten Master Password (Zero-Reset)": [
        "1. Retrieve your offline SHIELD-XXXXX-... Emergency Recovery Kit.",
        "2. On the S.H.I.E.L.D. Lock Screen, click 'Recover Vault with Emergency Recovery Key...'.",
        "3. Enter the Recovery Key and set a brand-new strong Master Password (>= 12 chars).",
        "4. After unlock, immediately rotate your Emergency Recovery Kit in Backup & Recovery.",
        "5. Run a Full Integrity Check and export a fresh Ed25519-signed encrypted backup.",
    ],
    "Corrupted Database / Tamper Rollback": [
        "1. Do NOT delete or overwrite the damaged database before preserving a forensic copy.",
        "2. Open Backup & Recovery -> Inspect Rolling SQLite Snapshots in the snapshots/ directory.",
        "3. Or select your newest Ed25519-signed `.shield.enc` backup and click 'Verify Backup'.",
        "4. Confirm SHA-256 checksum & Ed25519 signature pass before restoring.",
        "5. Restore records, rotate Master Password, and re-verify all 5 Cybersecurity Pillars.",
    ],
    "New Machine / Device Loss Migration": [
        "1. On the new machine, install Python >= 3.11 and run: python -m pip install --user -r requirements.txt.",
        "2. Copy your latest verified `.shield.enc` backup (or link your Google Drive E2EE sync file).",
        "3. Initialize S.H.I.E.L.D. and restore from the verified encrypted backup.",
        "4. Open Identity & Devices -> Revoke the lost/retired device immediately.",
        "5. Verify Vault MFA works on the new device and run a DR Readiness Drill.",
    ],
}


def render_governance_report_markdown(
    *,
    policy_score: int,
    policy_checks: list[PolicyCheckResult],
    risks: list[RiskRecord],
    incidents: list[IncidentCase],
    patches: list[PatchCheckItem],
    dr_drill: dict[str, Any] | None = None,
) -> str:
    """Export a strictly redacted Governance, Risk, IR, Patching & DR report in Markdown."""
    lines = [
        "# P.U.L.S.E. S.H.I.E.L.D. — Governance, Risk, Incident Response & Patch Report",
        "",
        f"- **Generated:** {_utc_now()}",
        f"- **Security Policy Compliance:** {policy_score}%",
        f"- **Tracked Risks:** {len(risks)} ({sum(1 for r in risks if r.status == 'Open')} open)",
        f"- **Incident Cases:** {len(incidents)} ({sum(1 for i in incidents if i.phase != 'Closed')} active)",
        "",
        "## 1. Security Policy Compliance",
    ]
    for c in policy_checks:
        lines.append(f"- **[{c.status}] {c.policy_id} — {c.name}:** {c.detail}")

    lines.extend(["", "## 2. Risk Register (Likelihood × Impact)"])
    if not risks:
        lines.append("- No active risks recorded.")
    for r in risks:
        lines.append(
            f"- **[{r.rating.upper()} {r.score}/25 | {r.status}] {r.id} — {r.title}** ({r.category}): {r.mitigation}"
        )

    lines.extend(["", "## 3. Incident Response Cases"])
    if not incidents:
        lines.append("- No incident cases logged.")
    for inc in incidents:
        done = sum(1 for s in inc.steps if s.get("done"))
        lines.append(
            f"- **[{inc.severity.upper()} | Phase: {inc.phase}] {inc.id} — {inc.title}** ({done}/{len(inc.steps)} steps complete)"
        )

    lines.extend(["", "## 4. Patching & Dependency Security Posture"])
    for p in patches:
        lines.append(f"- **[{p.status}] {p.component}:** {p.installed_version} (baseline {p.minimum_secure}) — {p.recommendation}")

    if dr_drill:
        lines.extend(["", "## 5. Latest Disaster Recovery Readiness Drill"])
        lines.append(f"- **Status:** {dr_drill.get('overall_status', 'UNKNOWN')} ({dr_drill.get('executed_at', '')})")
        for step in dr_drill.get("checks", []):
            lines.append(f"- **[{step['status']}] {step['name']}:** {step['detail']}")

    return "\n".join(lines)
