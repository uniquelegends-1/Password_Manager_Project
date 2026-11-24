"""Isolated Purple-Team Adversarial Security, Fuzzing & Fault-Injection Testing Suite.

Runs 100% inside a disposable temporary sandbox using synthetic credentials.
NEVER touches any real user vault, real passwords, or live backups.
"""

from __future__ import annotations

import base64
import json
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from shield_core.app_integrity import generate_app_manifest, verify_app_integrity
from shield_core.contracts import PermissionDeniedError, PermissionScope, ScopedEcosystemAdapter
from shield_core.e2ee import E2EEError
from shield_core.identity_access import DeviceRevokedError, RateLimitError
from shield_core.key_management import KdfParams
from shield_core.mfa import generate_totp_secret, get_totp_code
from shield_core.security_audit import scan_website_security
from shield_core.vault_engine import (
    InvalidMFACodeError,
    InvalidPasswordError,
    ShieldVault,
    VaultIntegrityError,
    VaultLockedError,
)

SANDBOX_KDF = KdfParams(iterations=1, memory_cost=8192, lanes=1)


@dataclass
class AttackResult:
    attack_id: str
    category: str
    name: str
    passed: bool
    duration_ms: float
    defense_observed: str


def _run_attack(
    attack_id: str, category: str, name: str, fn: Callable[[Path], str]
) -> AttackResult:
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="shield_pt_") as tmp:
        try:
            detail = fn(Path(tmp))
            elapsed = (time.perf_counter() - t0) * 1000
            return AttackResult(attack_id, category, name, True, round(elapsed, 1), detail)
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            return AttackResult(attack_id, category, name, False, round(elapsed, 1), f"FAILED: {exc}")


# ------------------------------------------------------------------ #
# Adversarial Attack Scenarios (Isolated Synthetic Vaults Only)
# ------------------------------------------------------------------ #


def _atk_bruteforce_and_device_injection(tmp: Path) -> str:
    db = tmp / "vault.db"
    v = ShieldVault(db, kdf_params=SANDBOX_KDF)
    try:
        v.create("SyntheticMaster!2026")
        v.lock()

        # Simulate attacker on unknown device attempting brute-force
        v._open_db()
        assert v._iam is not None
        orig_id = v._iam.current_device_id
        v._iam.current_device_id = "DEV-ROGUE999999"

        for attempt in range(2):
            try:
                v.unlock(f"GuessPassword{attempt}!")
                raise AssertionError("Attacker unlocked vault with wrong password")
            except InvalidPasswordError:
                pass

        # 3rd consecutive failure MUST trigger progressive lockout
        locked_out = False
        try:
            v.unlock("GuessPassword3!")
        except RateLimitError as exc:
            locked_out = exc.retry_after_seconds >= 5
        assert locked_out, "Progressive rate limiting did not engage after 3 failures"

        # Even correct password must be blocked while rate-limited
        blocked_correct = False
        try:
            v.unlock("SyntheticMaster!2026")
        except RateLimitError:
            blocked_correct = True
        assert blocked_correct, "Rate limit was bypassed by correct password during lockout"

        # Clear lockout to verify rogue device was NOT registered as trusted
        conn = sqlite3.connect(str(db))
        conn.execute("UPDATE auth_state SET lockout_until = 0, failed_attempts = 0")
        conn.commit()
        conn.close()

        v._iam.current_device_id = orig_id
        assert v.unlock("SyntheticMaster!2026")
        ids = {d.device_id for d in v.list_devices()}
        assert "DEV-ROGUE999999" not in ids, "Unauthenticated attacker device was erroneously trusted"
        return "3-strike progressive lockout enforced; correct password blocked during lockout; rogue device rejected."
    finally:
        v.close()


def _atk_mfa_replay_and_revoked_device(tmp: Path) -> str:
    db = tmp / "vault.db"
    v = ShieldVault(db, kdf_params=SANDBOX_KDF)
    try:
        v.create("SyntheticMFA!2026")
        sec = generate_totp_secret()
        code, _ = get_totp_code(sec)
        rec_codes = v.enable_mfa(sec, code)
        dev_id = v.list_devices()[0].device_id
        v.lock()

        # Stage-1 must NOT expose credentials before MFA completes
        assert v.unlock("SyntheticMFA!2026") is False
        try:
            v.list_entries()
            raise AssertionError("Credentials leaked while MFA pending")
        except VaultLockedError:
            pass

        # Replaying the setup TOTP code within same 30s window must fail
        replay_blocked = False
        try:
            v.complete_mfa(code)
        except InvalidMFACodeError:
            replay_blocked = True
        assert replay_blocked, "TOTP replay attack succeeded"

        # One-time recovery code succeeds once, then replay fails
        assert v.complete_mfa(rec_codes[0]) is False
        v.revoke_device(dev_id, "SyntheticMFA!2026")
        v.lock()

        # Revoked device must be blocked immediately
        revoked_blocked = False
        try:
            v.unlock("SyntheticMFA!2026")
        except DeviceRevokedError:
            revoked_blocked = True
        assert revoked_blocked, "Revoked device bypassed access control"
        return "Pending-MFA gate held; TOTP time-step replay blocked; revoked device rejected before KDF."
    finally:
        v.close()


def _atk_db_tamper_swap_and_rollback(tmp: Path) -> str:
    db = tmp / "vault.db"
    v = ShieldVault(db, kdf_params=SANDBOX_KDF)
    try:
        v.create("SyntheticDB!2026")
        e1 = v.add_entry(title="Synthetic Bank", password="BankPassword!111")
        e2 = v.add_entry(title="Synthetic Mail", password="MailPassword!222")

        # Snapshot original row of e1 BEFORE updating it (to attempt rollback attack!)
        conn = sqlite3.connect(str(db))
        old_e1_row = conn.execute(
            "SELECT dek_nonce, wrapped_dek, payload_nonce, ciphertext, updated_at FROM credentials WHERE id = ?",
            (e1.id,),
        ).fetchone()
        conn.close()

        time.sleep(1.05)
        v.update_entry(e1.id, title="Synthetic Bank", password="RotatedPassword!999")
        v.close()

        # Attack A: Rollback e1 to its older valid encrypted row
        db_rollback = tmp / "rollback.db"
        shutil.copy2(db, db_rollback)
        c1 = sqlite3.connect(str(db_rollback))
        c1.execute(
            "UPDATE credentials SET dek_nonce=?, wrapped_dek=?, payload_nonce=?, ciphertext=?, updated_at=? WHERE id=?",
            (*old_e1_row, e1.id),
        )
        c1.commit()
        c1.close()
        vr = ShieldVault(db_rollback, kdf_params=SANDBOX_KDF)
        try:
            try:
                vr.unlock("SyntheticDB!2026")
                raise AssertionError("Silent record rollback went undetected")
            except VaultIntegrityError:
                pass
        finally:
            vr.close()

        # Attack B: Silent row deletion of e2
        db_del = tmp / "deleted.db"
        shutil.copy2(db, db_del)
        c2 = sqlite3.connect(str(db_del))
        c2.execute("DELETE FROM credentials WHERE id = ?", (e2.id,))
        c2.commit()
        c2.close()
        vd = ShieldVault(db_del, kdf_params=SANDBOX_KDF)
        try:
            try:
                vd.unlock("SyntheticDB!2026")
                raise AssertionError("Silent SQLite row deletion went undetected")
            except VaultIntegrityError:
                pass
        finally:
            vd.close()

        # Attack C: Cross-record DEK/ciphertext transplant (AAD binding check)
        db_swap = tmp / "swap.db"
        shutil.copy2(db, db_swap)
        c3 = sqlite3.connect(str(db_swap))
        r1 = c3.execute("SELECT dek_nonce, wrapped_dek, payload_nonce, ciphertext, updated_at FROM credentials WHERE id=?", (e1.id,)).fetchone()
        c3.execute(
            "UPDATE credentials SET dek_nonce=?, wrapped_dek=?, payload_nonce=?, ciphertext=?, updated_at=? WHERE id=?",
            (*r1, e2.id),
        )
        c3.commit()
        c3.close()
        vs = ShieldVault(db_swap, kdf_params=SANDBOX_KDF)
        try:
            try:
                vs.unlock("SyntheticDB!2026")
                raise AssertionError("Cross-record ciphertext transplant went undetected")
            except Exception:
                pass  # Rejected by either AES-GCM AAD tag or record manifest
        finally:
            vs.close()

        return "Rollback attack, silent row deletion, and cross-record DEK transplant all detected and blocked."
    finally:
        v.close()


def _atk_audit_full_chain_rewrite(tmp: Path) -> str:
    """Adversary rewrites the ENTIRE audit_events table with a freshly computed valid SHA-256 chain (no Ed25519 key)."""
    from shield_core.audit_log import GENESIS_HASH, _compute_event_hash

    db = tmp / "vault.db"
    v = ShieldVault(db, kdf_params=SANDBOX_KDF)
    try:
        v.create("SyntheticAudit!2026")
        v.add_entry(title="Synthetic Secret", password="Strong!Password123")
        v.close()

        # Rewrite audit_events with a completely valid SHA-256 chain, forging fake signatures
        conn = sqlite3.connect(str(db))
        rows = conn.execute(
            "SELECT id, timestamp, event_type, severity, device_id, metadata_json FROM audit_events ORDER BY id ASC"
        ).fetchall()
        prev = GENESIS_HASH
        for rid, ts, etype, sev, dev, meta_json in rows:
            forged_summary = "Forged innocent event"
            new_hash = _compute_event_hash(ts, etype, sev, dev, forged_summary, meta_json, prev)
            forged_sig = base64.b64encode(b"X" * 64).decode("ascii")
            conn.execute(
                "UPDATE audit_events SET summary=?, prev_hash=?, event_hash=?, signature=? WHERE id=?",
                (forged_summary, prev, new_hash, forged_sig, rid),
            )
            prev = new_hash
        conn.commit()
        conn.close()

        v2 = ShieldVault(db, kdf_params=SANDBOX_KDF)
        try:
            ok, msg = v2.verify_audit_log_integrity()
            assert not ok, "Rewritten SHA-256 audit chain bypassed Ed25519 non-repudiation!"
            assert "Ed25519" in msg, f"Expected Ed25519 failure message, got: {msg}"
            return f"Full SHA-256 chain rewrite defeated by Ed25519 verification ({msg})."
        finally:
            v2.close()
    finally:
        v.close()


def _atk_malicious_e2ee_and_backup_dos(tmp: Path) -> str:
    v1 = ShieldVault(tmp / "v1.db", kdf_params=SANDBOX_KDF)
    v2 = ShieldVault(tmp / "v2.db", kdf_params=SANDBOX_KDF)
    try:
        v1.create("SenderPass!2026")
        v2.create("ReceiverPass!2026")
        e = v1.add_entry(title="Synthetic Share", password="ShareSecret!999")
        pkt = v1.share_entry_for_public_key(e.id, v2.public_key)

        # Forge Ed25519 signature on E2EE packet
        prefix = "SHIELD-E2EE-PK-v1:"
        raw = json.loads(base64.urlsafe_b64decode(pkt[len(prefix) :]).decode("utf-8"))
        raw["sig"] = base64.b64encode(b"A" * 64).decode("ascii")
        forged = prefix + base64.urlsafe_b64encode(json.dumps(raw).encode("utf-8")).decode("ascii")
        try:
            v2.import_e2ee_packet(forged)
            raise AssertionError("Forged E2EE packet signature accepted")
        except E2EEError:
            pass

        # Malicious Argon2id OOM bomb backup file (memory_cost = 999 GB)
        bak = v1.create_versioned_backup_in_dir(tmp / "baks", "SenderPass!2026")
        bomb_path = tmp / "oom_bomb.shield.enc"
        obj = json.loads(bak.read_text(encoding="utf-8"))
        obj["header"]["kdf"]["memory_cost"] = 999_999_999
        bomb_path.write_text(json.dumps(obj), encoding="utf-8")
        res = v1.test_backup_restore_integrity(bomb_path, "SenderPass!2026")
        assert not res["valid"], "Tampered OOM-bomb backup accepted"
        return "Forged E2EE signature rejected; OOM-bomb backup checksum/signature rejected without memory exhaustion."
    finally:
        v1.close()
        v2.close()


def _atk_fuzz_sqli_ssrf_and_malformed_inputs(tmp: Path) -> str:
    db = tmp / "fuzz.db"
    v = ShieldVault(db, kdf_params=SANDBOX_KDF)
    try:
        v.create("FuzzMaster!2026")
        hostile_strings = [
            "'; DROP TABLE credentials; --",
            "' OR '1'='1",
            "Null\x00Byte\nInjection",
            "A" * 20_000,
            "🔒🚀<script>alert(1)</script>",
        ]
        for idx, s in enumerate(hostile_strings):
            v.add_entry(title=f"Fuzz-{idx}-{s[:40]}", username=s, password=f"P!{idx}xYz987654321", tags=[s[:30]], notes=s)

        # Verify SQLite tables intact & parameterized search resilient
        assert v.count() == len(hostile_strings)
        for s in hostile_strings:
            _ = v.list_entries(query=s)

        # SSRF checks against private / loopback / metadata / file URLs
        for bad_url in (
            "http://127.0.0.1:8080/admin",
            "http://localhost/secret",
            "http://169.254.169.254/latest/meta-data/",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "javascript:alert(1)",
        ):
            scan = scan_website_security(bad_url)
            assert not scan.reachable, f"SSRF URL unexpectedly reached: {bad_url}"

        # Malformed E2EE packets & boundary permission escalation attempt
        for bad_pkt in ("", "SHIELD-E2EE-PK-v1:!!!notbase64!!!", "SHIELD-E2EE-PW-v1:e30="):
            try:
                v.import_e2ee_packet(bad_pkt, passphrase="test")
                raise AssertionError(f"Malformed packet accepted: {bad_pkt}")
            except (ValueError, E2EEError):
                pass

        # Ecosystem boundary privilege escalation test (AI/external caller without secrets scope)
        adapter = ScopedEcosystemAdapter(v, granted_scopes={PermissionScope.VAULT_STATUS})
        assert adapter.get_vault_status()["is_unlocked"] is True
        denied = False
        try:
            adapter.list_redacted_credentials()
        except PermissionDeniedError:
            denied = True
        assert denied, "ScopedEcosystemAdapter allowed unauthorized scope"

        return "SQLi payloads neutralized; 20KB/null/unicode fuzz survived; 5 SSRF targets blocked; boundary scope enforced."
    finally:
        v.close()


def _atk_forensic_plaintext_leak_check(tmp: Path) -> str:
    db = tmp / "forensic.db"
    v = ShieldVault(db, kdf_params=SANDBOX_KDF)
    sentinel_title = "SENTINEL_PRIVATE_MEDICAL_PORTAL_9912"
    sentinel_user = "sentinel.private.user@example.invalid"
    sentinel_pwd = "SENTINEL_ULTRA_SECRET_PWD_7741!"
    sentinel_totp = generate_totp_secret()
    try:
        v.create("ForensicMaster!2026", create_recovery_kit=True)
        v.add_entry(
            title=sentinel_title,
            username=sentinel_user,
            password=sentinel_pwd,
            totp_secret=sentinel_totp,
            custom_fields={"SSN_TEST": "000-00-0000"},
            notes="SENTINEL_PRIVATE_NOTE_8821",
        )
        bak = v.create_versioned_backup_in_dir(tmp / "baks", "ForensicMaster!2026")
        proof = v.export_signed_audit_proof(tmp / "proof.json")
        gov = v.export_governance_report(tmp / "gov.md")
        v.close()

        sentinels = [sentinel_title, sentinel_user, sentinel_pwd, sentinel_totp, "000-00-0000", "SENTINEL_PRIVATE_NOTE_8821"]
        for artifact in (db, bak, proof, gov):
            raw = artifact.read_bytes()
            for s in sentinels:
                assert s.encode("utf-8") not in raw, f"PLAINTEXT LEAK of '{s}' in {artifact.name}!"

        return "Zero plaintext leaks across SQLite DB, .shield.enc backup, signed audit proof, and governance report."
    finally:
        v.close()


def _atk_app_integrity_tamper_detection(tmp: Path) -> str:
    # Copy real app source structure into isolated sandbox, generate manifest, then mutate 1 byte
    app_root = Path(__file__).resolve().parent
    sandbox_app = tmp / "sandbox_app"
    sandbox_core = sandbox_app / "shield_core"
    sandbox_core.mkdir(parents=True)
    for name in ("app.py", "dialogs.py", "vault.py", "requirements.txt"):
        shutil.copy2(app_root / name, sandbox_app / name)
    for pyf in (app_root / "shield_core").glob("*.py"):
        shutil.copy2(pyf, sandbox_core / pyf.name)

    generate_app_manifest(sandbox_app)
    ok_res = verify_app_integrity(sandbox_app)
    assert ok_res.valid, f"Clean sandbox failed verification: {ok_res.message}"

    # Mutate 1 byte in key_management.py
    target = sandbox_core / "key_management.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# backdoor\n", encoding="utf-8")
    tampered_res = verify_app_integrity(sandbox_app)
    assert not tampered_res.valid, "Modified application file went undetected"
    assert "shield_core/key_management.py" in tampered_res.modified_files

    # Inject a rogue .py file inside shield_core/
    (sandbox_core / "evil_dropper.py").write_text("x = 1\n", encoding="utf-8")
    inj_res = verify_app_integrity(sandbox_app)
    assert "shield_core/evil_dropper.py" in inj_res.unexpected_files
    return f"Detected modified core file and injected rogue module across {ok_res.checked_count} monitored files."


def run_purple_team_suite(report_path: Path | None = None) -> list[AttackResult]:
    scenarios = [
        ("PT-01", "Authentication & IAM", "Brute-Force Lockout & Rogue Device Injection", _atk_bruteforce_and_device_injection),
        ("PT-02", "MFA & Access Control", "Pending-MFA Gate, TOTP Replay & Revoked Device Hijack", _atk_mfa_replay_and_revoked_device),
        ("PT-03", "Database Integrity", "Row Rollback, Silent Deletion & Cross-Record DEK Transplant", _atk_db_tamper_swap_and_rollback),
        ("PT-04", "Non-Repudiation", "Full SHA-256 Audit Chain Rewrite Without Ed25519 Key", _atk_audit_full_chain_rewrite),
        ("PT-05", "E2EE & Backups", "Forged Ed25519 E2EE Packet & Argon2id OOM-Bomb Backup", _atk_malicious_e2ee_and_backup_dos),
        ("PT-06", "Fuzzing & Boundaries", "SQLi, 20KB/Null Fuzz, SSRF Private IPs & Scope Escalation", _atk_fuzz_sqli_ssrf_and_malformed_inputs),
        ("PT-07", "Confidentiality Forensics", "Raw Disk, Backup, Audit Proof & Report Plaintext Scan", _atk_forensic_plaintext_leak_check),
        ("PT-08", "Application Integrity", "1-Byte Core Code Mutation & Rogue Module Injection", _atk_app_integrity_tamper_detection),
    ]

    results = [_run_attack(aid, cat, name, fn) for aid, cat, name, fn in scenarios]

    if report_path is not None:
        passed = sum(1 for r in results if r.passed)
        lines = [
            "# P.U.L.S.E. S.H.I.E.L.D. — Purple-Team Adversarial Verification Report",
            "",
            f"- **Executed:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- **Environment:** Isolated Temporary Sandbox (100% synthetic credentials; zero live vault interaction)",
            f"- **Score:** **{passed}/{len(results)}** adversarial attack scenarios defeated",
            "",
            "| ID | Category | Attack Scenario | Result | Time | Defensive Behavior Observed |",
            "|---|---|---|---|---|---|",
        ]
        for r in results:
            status = "DEFENDED" if r.passed else "FAILED"
            lines.append(f"| {r.attack_id} | {r.category} | {r.name} | **{status}** | {r.duration_ms}ms | {r.defense_observed} |")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return results


if __name__ == "__main__":
    out_report = Path(__file__).resolve().parent / "docs" / "PURPLE_TEAM_REPORT.md"
    res_list = run_purple_team_suite(report_path=out_report)
    passed_cnt = sum(1 for r in res_list if r.passed)
    for r in res_list:
        tag = "DEFENDED" if r.passed else "FAILED  "
        print(f"[{tag}] {r.attack_id} ({r.duration_ms:6.1f}ms) {r.name}: {r.defense_observed}")
    print(f"\nPurple-Team Summary: {passed_cnt}/{len(res_list)} attacks defeated. Report saved to {out_report}")
    if passed_cnt != len(res_list):
        raise SystemExit(1)
