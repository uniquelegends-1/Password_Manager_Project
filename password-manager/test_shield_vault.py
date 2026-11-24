"""Comprehensive test suite for P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T."""

from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from shield_core.adaptive_security import AdaptivePolicyConfig
from shield_core.e2ee import E2EEError
from shield_core.google_sync import export_google_passwords_csv, parse_google_passwords_csv, secure_delete_file
from shield_core.governance_ops import RiskRecord, SecurityPolicyConfig
from shield_core.identity_access import DeviceRevokedError, RateLimitError
from shield_core.key_management import KdfParams
from shield_core.mfa import build_otpauth_uri, build_qr_matrix, generate_totp_secret, get_totp_code, normalize_totp_secret
from shield_core.password_gen import (
    AMBIGUOUS_CHARS,
    EXTENDED_SYMBOLS,
    SITE_POLICY_PRESETS,
    calculate_entropy,
    generate_from_policy,
    generate_passphrase,
    generate_password,
)
from shield_core.security_audit import audit_vault, match_known_site_advisory
from shield_core.vault_engine import (
    InvalidMFACodeError,
    InvalidPasswordError,
    ShieldVault,
    VaultIntegrityError,
    VaultLockedError,
)

# Fast Argon2id parameters for automated tests (production uses 64 MiB, 3 iters, 4 lanes)
TEST_KDF = KdfParams(iterations=1, memory_cost=8192, lanes=1)


class ShieldVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self._tmp.name)
        self.db_path = self.tmp_dir / "shield_test.db"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_argon2id_sqlite_per_record_dek_and_zero_plaintext_on_disk(self) -> None:
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        vault.create("MasterPassphrase!2026")
        totp = generate_totp_secret()
        entry = vault.add_entry(
            title="GitHub Enterprise",
            entry_type="Website",
            category="Work",
            tags=["dev", "critical"],
            favorite=True,
            username="user@example.com",
            password="Unique!SuperSecret#Password2026",
            url="https://github.com",
            totp_secret=totp,
            passkey_enabled=True,
            custom_fields={"SSH PIN": "8492", "Org": "PULSE"},
            notes="Hardware key backup stored in safe",
        )
        self.assertEqual(vault.count(), 1)

        # Verify zero personal data / credential metadata leaks into raw SQLite bytes (including audit_events!)
        vault.close()
        raw_bytes = self.db_path.read_bytes()
        self.assertNotIn(b"GitHub Enterprise", raw_bytes)
        self.assertNotIn(b"Unique!SuperSecret#Password2026", raw_bytes)
        self.assertNotIn(b"user@example.com", raw_bytes)
        self.assertNotIn(totp.encode("ascii"), raw_bytes)
        self.assertNotIn(b"8492", raw_bytes)

        reopened = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        self.assertTrue(reopened.unlock("MasterPassphrase!2026"))
        loaded = reopened.get_entry(entry.id)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertTrue(loaded.favorite)
        self.assertEqual(loaded.tags, ["dev", "critical"])
        self.assertEqual(loaded.custom_fields["SSH PIN"], "8492")
        self.assertTrue(loaded.passkey_enabled)
        self.assertEqual(loaded.totp_secret, totp)
        reopened.close()

    def test_bruteforce_rate_limiting_and_device_revocation(self) -> None:
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        vault.create("StrongMaster!2026")
        dev = vault.list_devices()[0]
        self.assertEqual(dev.status, "trusted")
        vault.lock()

        # 2 wrong attempts -> InvalidPasswordError; 3rd -> progressive RateLimitError
        with self.assertRaises(InvalidPasswordError):
            vault.unlock("WrongPass1!")
        with self.assertRaises(InvalidPasswordError):
            vault.unlock("WrongPass2!")
        with self.assertRaises(RateLimitError) as ctx:
            vault.unlock("WrongPass3!")
        self.assertGreaterEqual(ctx.exception.retry_after_seconds, 5)

        # Subsequent attempt while locked out is immediately rate-limited
        with self.assertRaises(RateLimitError):
            vault.unlock("StrongMaster!2026")

        # Clear lockout directly for device revocation test
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("UPDATE auth_state SET lockout_until = 0, failed_attempts = 0")
        conn.commit()
        conn.close()

        vault.unlock("StrongMaster!2026")
        vault.revoke_device(dev.device_id, "StrongMaster!2026")
        vault.lock()

        with self.assertRaises(DeviceRevokedError):
            vault.unlock("StrongMaster!2026")
        vault.close()

    def test_zero_reset_emergency_recovery_kit(self) -> None:
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        rec_key = vault.create("OriginalMaster!2026", create_recovery_kit=True)
        self.assertIsNotNone(rec_key)
        assert rec_key is not None
        self.assertTrue(vault.has_recovery_kit)
        vault.add_entry(title="Bank Account", password="BankSecret!999", category="Finance")
        vault.lock()

        # Wrong recovery key rejected
        with self.assertRaises(InvalidPasswordError):
            vault.recover_vault_with_recovery_key("SHIELD-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG-HHHHH", "NewMaster!999")

        # Valid recovery key unwraps VMK and sets new master password
        vault.recover_vault_with_recovery_key(rec_key, "BrandNewMaster!2026")
        self.assertTrue(vault.is_unlocked)
        self.assertEqual(vault.list_entries()[0].password, "BankSecret!999")
        vault.lock()

        # Old master password no longer works; new one works
        with self.assertRaises(InvalidPasswordError):
            vault.unlock("OriginalMaster!2026")
        self.assertTrue(vault.unlock("BrandNewMaster!2026"))
        vault.close()

    def test_mfa_totp_anti_replay_and_recovery_codes(self) -> None:
        secret = generate_totp_secret()
        uri = build_otpauth_uri(secret)
        self.assertEqual(normalize_totp_secret(uri), secret)
        self.assertIsNotNone(build_qr_matrix(uri))

        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        vault.create("MfaMaster!2026")
        code, _ = get_totp_code(secret)
        recovery_codes = vault.enable_mfa(secret, code)
        self.assertEqual(len(recovery_codes), 8)
        vault.lock()

        # Stage 1 succeeds but holds vault locked until MFA
        self.assertFalse(vault.unlock("MfaMaster!2026"))
        self.assertTrue(vault.is_mfa_pending)
        with self.assertRaises(VaultLockedError):
            vault.list_entries()

        # Anti-replay: re-using the exact same TOTP time-step used during setup must be blocked!
        with self.assertRaises(InvalidMFACodeError):
            vault.complete_mfa(code)

        # Unlock via one-time recovery code (consumed after use)
        self.assertFalse(vault.complete_mfa(recovery_codes[0]))
        self.assertTrue(vault.is_unlocked)
        self.assertEqual(vault.remaining_mfa_recovery_codes, 7)
        vault.lock()

        # Replaying consumed recovery code fails
        self.assertFalse(vault.unlock("MfaMaster!2026"))
        with self.assertRaises(InvalidMFACodeError):
            vault.complete_mfa(recovery_codes[0])
        vault.close()

    def test_tamper_evident_hash_chained_audit_log_and_redaction(self) -> None:
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        vault.create("AuditMaster!2026")
        vault.add_entry(title="SecretAPI", entry_type="API Key / Token", password="TOP_SECRET_PASSWORD_999")
        ok, msg = vault.verify_audit_log_integrity()
        self.assertTrue(ok, msg)

        # Ensure secrets never appear in audit events
        events = vault.list_audit_events()
        self.assertTrue(len(events) >= 2)
        for ev in events:
            self.assertNotIn("TOP_SECRET_PASSWORD_999", ev.summary)
            self.assertNotIn("AuditMaster!2026", ev.summary)

        # Tamper directly with an audit row -> hash chain verification MUST fail
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("UPDATE audit_events SET summary = 'Forged clean event' WHERE id = 1")
        conn.commit()
        conn.close()

        ok2, _msg2 = vault.verify_audit_log_integrity()
        self.assertFalse(ok2)
        vault.close()

    def test_adaptive_security_policy_levels(self) -> None:
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        vault.create("AdaptiveMaster!2026")

        req_user = vault.evaluate_security_action("view_username")
        self.assertFalse(req_user.require_master_password)

        req_exp = vault.evaluate_security_action("export_vault")
        self.assertTrue(req_exp.require_master_password)
        self.assertEqual(req_exp.level, "strong")

        # Turn on re-auth for Finance password reveals
        cfg = AdaptivePolicyConfig(require_reauth_for_sensitive_reveal=True)
        vault.update_adaptive_config(cfg, "AdaptiveMaster!2026")
        req_fin = vault.evaluate_security_action("reveal_password", entry_category="Finance")
        req_gen = vault.evaluate_security_action("reveal_password", entry_category="General")
        self.assertTrue(req_fin.require_master_password)
        self.assertFalse(req_gen.require_master_password)
        vault.close()

    def test_generator_site_policies_and_passphrases(self) -> None:
        pwd = generate_password(
            length=26, use_extended=True, custom_chars="§", exclude_ambiguous=True, min_digits=4, min_symbols=3
        )
        self.assertEqual(len(pwd), 26)
        self.assertTrue(any(c in EXTENDED_SYMBOLS for c in pwd))
        self.assertFalse(any(c in AMBIGUOUS_CHARS for c in pwd))
        self.assertGreater(calculate_entropy(pwd), 100)

        for name, pol in SITE_POLICY_PRESETS.items():
            out = generate_from_policy(pol)
            self.assertEqual(len(out), pol.length, f"Policy {name} length mismatch")

        phrase = generate_passphrase(word_count=5, separator="-", capitalize=True, include_number=True, include_symbol=True)
        self.assertEqual(len(phrase.split("-")), 5)

    def test_health_intelligence_reuse_and_priority_ranking(self) -> None:
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        vault.create("IntelMaster!2026")
        e1 = vault.add_entry(title="Yahoo", username="u@yahoo.com", password="password123", url="http://yahoo.com", category="Email")
        vault.add_entry(title="OldWork", username="u@work.com", password="password123", url="https://lastpass.com", category="Work")
        vault.add_entry(
            title="Fortress Bank",
            username="u_bank",
            password=generate_password(length=24),
            url="https://securebank.example",
            category="Finance",
            totp_secret=generate_totp_secret(),
        )

        self.assertEqual(len(vault.find_password_reuse("password123", exclude_entry_id=e1.id)), 1)
        self.assertIsNotNone(match_known_site_advisory("https://lastpass.com"))

        report = audit_vault(vault.list_entries())
        self.assertEqual(report.strong_count, 1)
        self.assertEqual(report.reused_count, 2)
        self.assertGreaterEqual(report.weak_count, 2)
        self.assertGreaterEqual(report.potentially_exposed_count, 2)
        # Highest risk ranked first
        self.assertGreater(report.entry_results[0].risk_score, report.entry_results[-1].risk_score)
        md = report.to_markdown()
        self.assertNotIn("password123", md)
        vault.close()

    def test_versioned_encrypted_backup_integrity_restore_e2ee_and_google_csv(self) -> None:
        alice = ShieldVault(self.tmp_dir / "alice.db", kdf_params=TEST_KDF)
        bob = ShieldVault(self.tmp_dir / "bob.db", kdf_params=TEST_KDF)
        alice.create("AliceMaster!2026")
        bob.create("BobMaster!2026")

        e = alice.add_entry(title="Cloud Console", username="admin", password="UniqueCloud!Pass#2026", url="https://console.cloud.google.com")

        # Versioned encrypted backup + integrity verification
        bak_path = alice.create_versioned_backup_in_dir(self.tmp_dir / "backups", "AliceMaster!2026")
        self.assertNotIn("UniqueCloud!Pass#2026", bak_path.read_text(encoding="utf-8"))
        ok_res = alice.test_backup_restore_integrity(bak_path, "AliceMaster!2026")
        self.assertTrue(ok_res["valid"])
        self.assertEqual(ok_res["entry_count"], 1)
        bad_res = alice.test_backup_restore_integrity(bak_path, "WrongPass!2026")
        self.assertFalse(bad_res["valid"])

        # Restore into Bob's vault
        res = bob.restore_from_encrypted_backup(bak_path, "AliceMaster!2026", merge=True)
        self.assertEqual(res["added"], 1)

        # X25519 E2EE share + passphrase E2EE share
        pk_pkt = alice.share_entry_for_public_key(e.id, bob.public_key)
        with self.assertRaises(E2EEError):
            alice.import_e2ee_packet(pk_pkt)
        imp_e = bob.import_e2ee_packet(pk_pkt)
        self.assertEqual(imp_e.password, "UniqueCloud!Pass#2026")

        pw_pkt = alice.share_entry_with_passphrase(e.id, "TempShare!2026")
        imp_e2 = bob.import_e2ee_packet(pw_pkt, passphrase="TempShare!2026")
        self.assertEqual(imp_e2.password, "UniqueCloud!Pass#2026")

        # Zero-knowledge E2EE sync merge
        sync_file = self.tmp_dir / "gdrive_sync.shield.enc"
        alice.sync_with_remote(sync_file, "AliceMaster!2026")
        alice2 = ShieldVault(self.tmp_dir / "alice_laptop.db", kdf_params=TEST_KDF)
        alice2.create("AliceMaster!2026")
        time.sleep(1.05)
        alice2.add_entry(title="Laptop WiFi", entry_type="Wi-Fi", password="WifiKey!88888")
        stats = alice2.sync_with_remote(sync_file, "AliceMaster!2026")
        self.assertEqual(stats["added_local"], 1)
        self.assertEqual(stats["total_entries"], 2)

        # Google CSV roundtrip + secure shred
        csv_path = self.tmp_dir / "google.csv"
        export_google_passwords_csv(alice.list_entries(), csv_path)
        items, _ = parse_google_passwords_csv(csv_path)
        self.assertEqual(len(items), 1)
        self.assertTrue(secure_delete_file(csv_path))
        self.assertFalse(csv_path.exists())

        alice.close()
        bob.close()
        alice2.close()

    def test_security_hardening_regressions(self) -> None:
        # 1. KdfParams upper-bound DoS clamping
        clamped = KdfParams.from_dict({"algorithm": "argon2id", "iterations": 999999, "memory_cost": 999999999, "lanes": 999})
        self.assertEqual(clamped.iterations, 20)
        self.assertEqual(clamped.memory_cost, 524288)
        self.assertEqual(clamped.lanes, 16)

        # 2. Failed login on a new device must NOT register it as trusted
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        rec_key = vault.create("HardenedMaster!2026", create_recovery_kit=True)
        assert rec_key is not None
        vault.lock()

        # Simulate a second device failing login
        vault._open_db()
        assert vault._iam is not None
        orig_dev_id = vault._iam.current_device_id
        vault._iam.current_device_id = "DEV-ATTACKER0001"
        with self.assertRaises(InvalidPasswordError):
            vault.unlock("WrongPassword!99")
        vault._iam.current_device_id = orig_dev_id
        self.assertTrue(vault.unlock("HardenedMaster!2026"))
        dev_ids = {d.device_id for d in vault.list_devices()}
        self.assertNotIn("DEV-ATTACKER0001", dev_ids)

        # 3. verify_reauth strictly enforces MFA when require_mfa=True
        sec = generate_totp_secret()
        code, _ = get_totp_code(sec)
        vault.enable_mfa(sec, code)
        with self.assertRaises(InvalidMFACodeError):
            vault.verify_reauth("HardenedMaster!2026", mfa_code="", require_mfa=True)
        with self.assertRaises(InvalidMFACodeError):
            vault.export_plaintext_json_file(self.tmp_dir / "nope.json", "HardenedMaster!2026", mfa_code="")
        vault.verify_reauth("HardenedMaster!2026", mfa_code=code, require_mfa=True)

        # 4. Emergency recovery rate limiting after 3 invalid recovery keys
        vault.lock()
        bad_rk = "SHIELD-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG-HHHHH"
        with self.assertRaises(InvalidPasswordError):
            vault.recover_vault_with_recovery_key(bad_rk, "NewMaster!2026")
        with self.assertRaises(InvalidPasswordError):
            vault.recover_vault_with_recovery_key(bad_rk, "NewMaster!2026")
        with self.assertRaises(RateLimitError):
            vault.recover_vault_with_recovery_key(bad_rk, "NewMaster!2026")
        vault.close()

    def test_five_pillars_cryptographic_guarantees(self) -> None:
        import base64
        import json

        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        vault.create("FivePillars!2026", create_recovery_kit=True)
        e1 = vault.add_entry(title="Primary Bank", password="Unique!Bank#Password2026", category="Finance")
        e2 = vault.add_entry(title="Cloud Root", password="Unique!Cloud#Password2026", category="Work")

        # --- Pillar 5 (Non-Repudiation): Ed25519-signed audit proof & forged-chain rejection ---
        ok, msg = vault.verify_audit_log_integrity()
        self.assertTrue(ok, msg)
        self.assertIn("Ed25519-signed", msg)
        proof_path = self.tmp_dir / "audit_proof.json"
        vault.export_signed_audit_proof(proof_path)
        proof_data = json.loads(proof_path.read_text(encoding="utf-8"))
        self.assertTrue(proof_data["chain_verified"])
        self.assertEqual(proof_data["signer_fingerprint"], vault.signing_fingerprint)

        # --- Pillar 4 (Authenticity): Ed25519-signed backups & E2EE share packets ---
        bak = vault.create_versioned_backup_in_dir(self.tmp_dir / "backups", "FivePillars!2026")
        ver = vault.test_backup_restore_integrity(bak, "FivePillars!2026")
        self.assertTrue(ver["valid"])
        self.assertTrue(ver["signature_verified"])
        self.assertEqual(ver["signer_fingerprint"], vault.signing_fingerprint)
        self.assertEqual(len(ver["sha256"]), 64)

        # Tampering with backup signature must fail Authenticity check
        tampered_bak = self.tmp_dir / "tampered.shield.enc"
        bak_json = json.loads(bak.read_text(encoding="utf-8"))
        bak_json["signature"] = base64.b64encode(b"0" * 64).decode("ascii")
        tampered_bak.write_text(json.dumps(bak_json), encoding="utf-8")
        bad_ver = vault.test_backup_restore_integrity(tampered_bak, "FivePillars!2026")
        self.assertFalse(bad_ver["valid"])

        # E2EE packet carries verified sender fingerprint & rejects forged signature
        bob = ShieldVault(self.tmp_dir / "bob_sig.db", kdf_params=TEST_KDF)
        bob.create("BobPillars!2026")
        pkt = vault.share_entry_for_public_key(e1.id, bob.public_key)
        bob.import_e2ee_packet(pkt)
        self.assertEqual(bob.last_e2ee_sender_fingerprint, vault.signing_fingerprint)

        # Forge signature inside E2EE packet -> must raise E2EEError
        prefix = "SHIELD-E2EE-PK-v1:"
        pkt_obj = json.loads(base64.urlsafe_b64decode(pkt[len(prefix) :]).decode("utf-8"))
        pkt_obj["sig"] = base64.b64encode(b"9" * 64).decode("ascii")
        forged_pkt = prefix + base64.urlsafe_b64encode(json.dumps(pkt_obj).encode("utf-8")).decode("ascii")
        with self.assertRaises(E2EEError):
            bob.import_e2ee_packet(forged_pkt)
        bob.close()

        # --- Pillar 3 (Availability): Rolling SQLite Snapshots & rotation ---
        for _ in range(4):
            vault.create_rolling_snapshot(max_keep=3)
        snaps = vault.list_rolling_snapshots()
        self.assertEqual(len(snaps), 3)

        # Live 5-pillar scorecard reports all 5 pillars
        pillars = {p["pillar"]: p["status"] for p in vault.evaluate_five_pillars()}
        self.assertEqual(set(pillars.keys()), {"Confidentiality", "Integrity", "Availability", "Authenticity", "Non-Repudiation"})
        self.assertEqual(pillars["Confidentiality"], "STRONG")
        self.assertEqual(pillars["Integrity"], "STRONG")
        self.assertEqual(pillars["Availability"], "STRONG")
        self.assertEqual(pillars["Non-Repudiation"], "STRONG")

        # --- Pillar 2 (Integrity): Silent SQLite row deletion detected on unlock! ---
        vault.close()
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("DELETE FROM credentials WHERE id = ?", (e2.id,))
        conn.commit()
        conn.close()

        reopened = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        with self.assertRaises(VaultIntegrityError):
            reopened.unlock("FivePillars!2026")
        reopened.close()

        # Verify rolling snapshot is still intact & unaffected (Disaster Recovery!)
        snap_vault = ShieldVault(snaps[0], kdf_params=TEST_KDF)
        self.assertTrue(snap_vault.unlock("FivePillars!2026"))
        self.assertEqual(snap_vault.count(), 2)
        snap_vault.close()

    def test_policies_risk_ir_patching_and_dr_drill(self) -> None:
        vault = ShieldVault(self.db_path, kdf_params=TEST_KDF)
        try:
            vault.create("GovOpsMaster!2026", create_recovery_kit=True)
            vault.add_entry(title="WeakSite", password="w3akPwd", url="http://example.com", category="Finance")

            # 1. Policies: evaluate compliance & update policy with strong auth
            score, checks = vault.evaluate_policy_compliance()
            self.assertLess(score, 100)
            pol_ids = {c.policy_id for c in checks}
            self.assertIn("POL-LEN", pol_ids)
            self.assertIn("POL-HTTPS", pol_ids)

            strict_pol = SecurityPolicyConfig(min_password_length=16, reuse_policy="block")
            vault.update_security_policy(strict_pol, "GovOpsMaster!2026")
            self.assertEqual(vault.security_policy.reuse_policy, "block")
            self.assertEqual(vault.security_policy.min_password_length, 16)

            # 2. Risk Register: auto-synthesized + custom risk tracking
            risks = vault.list_risk_register()
            self.assertTrue(len(risks) >= 1)
            custom = RiskRecord.from_dict(
                {"title": "Unencrypted USB transport", "category": "Operational", "likelihood": 4, "impact": 4, "mitigation": "Use BitLocker"}
            )
            vault.upsert_risk(custom)
            custom.status = "Mitigating"
            vault.upsert_risk(custom)
            found = [r for r in vault.list_risk_register() if r.id == custom.id]
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].status, "Mitigating")
            self.assertEqual(found[0].score, 16)

            # 3. Incident Response: playbook case lifecycle + Emergency Containment
            ext_dev = vault.register_external_device("Lost Laptop", "Windows 11", "GovOpsMaster!2026")
            inc = vault.open_incident("Lost or Compromised Trusted Device")
            self.assertEqual(inc.phase, "Detect")
            self.assertTrue(len(inc.steps) >= 5)
            inc.steps[0]["done"] = True
            inc.phase = "Contain"
            vault.update_incident(inc)
            self.assertEqual(vault.list_incidents()[0].phase, "Contain")

            containment = vault.execute_emergency_containment("GovOpsMaster!2026", revoke_other_devices=True)
            self.assertEqual(containment["revoked_devices"], 1)
            devs = {d.device_id: d.status for d in vault.list_devices()}
            self.assertEqual(devs[ext_dev.device_id], "revoked")

            # 4. Patching posture check
            patches = vault.get_patch_posture()
            comp_names = {p.component for p in patches}
            self.assertIn("Python Runtime", comp_names)
            self.assertIn("PyCA cryptography", comp_names)
            self.assertIn("OpenSSL / TLS Engine", comp_names)

            # 5. Live Disaster Recovery Readiness Drill + Redacted Governance Report
            drill = vault.run_dr_readiness_drill()
            self.assertEqual(drill["overall_status"], "PASS")
            self.assertEqual(len(drill["checks"]), 5)
            self.assertIsNotNone(vault.last_dr_drill)

            rep_path = self.tmp_dir / "gov_report.md"
            vault.export_governance_report(rep_path)
            md = rep_path.read_text(encoding="utf-8")
            self.assertIn("Governance, Risk, Incident Response & Patch Report", md)
            self.assertNotIn("GovOpsMaster!2026", md)
            self.assertNotIn("w3akPwd", md)

            # Verify audit chain remains 100% Ed25519-valid across all governance events
            ok, _msg = vault.verify_audit_log_integrity()
            self.assertTrue(ok)
        finally:
            vault.close()


if __name__ == "__main__":
    unittest.main()
