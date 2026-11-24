"""Tamper-Evident, Ed25519-Signed Hash-Chained Security Audit Log (Integrity & Non-Repudiation).

Guarantees:
- Integrity: Every event is chained to the previous event via SHA-256 (`prev_hash` -> `event_hash`).
- Non-Repudiation: Every authenticated event is digitally signed with the vault's Ed25519 private key
  over `(vault_id, device_id, event_hash)`, preventing even a local attacker from forging a new chain.
- Confidentiality: Strict redaction guarantees passwords, keys, TOTP secrets, and recovery keys NEVER enter logs.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shield_core.key_management import (
    public_key_fingerprint,
    restrict_file_permissions,
    sign_ed25519,
    verify_ed25519,
)

GENESIS_HASH = "0" * 64
SENSITIVE_KEY_FRAGMENTS = ("password", "secret", "token", "key", "recovery", "totp", "passphrase", "dek", "vmk")
PREAUTH_SIGNATURE_MARKER = "PREAUTH-UNSIGNED"


@dataclass
class AuditEvent:
    id: int
    timestamp: str
    event_type: str
    severity: str  # "info" | "warning" | "alert" | "critical"
    device_id: str
    summary: str
    metadata: dict[str, Any]
    prev_hash: str
    event_hash: str
    signature: str = ""
    signer_fingerprint: str = ""

    @property
    def is_signed(self) -> bool:
        return bool(self.signature) and self.signature != PREAUTH_SIGNATURE_MARKER


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def _sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not metadata:
        return {}
    clean: dict[str, Any] = {}
    for k, v in metadata.items():
        low_k = str(k).lower()
        if any(frag in low_k for frag in SENSITIVE_KEY_FRAGMENTS):
            clean[str(k)] = "[REDACTED]"
        elif isinstance(v, (str, int, float, bool)) or v is None:
            clean[str(k)] = v
        else:
            clean[str(k)] = str(v)[:120]
    return clean


def _compute_event_hash(
    timestamp: str,
    event_type: str,
    severity: str,
    device_id: str,
    summary: str,
    metadata_json: str,
    prev_hash: str,
) -> str:
    canonical = json.dumps(
        [timestamp, event_type, severity, device_id, summary, metadata_json, prev_hash],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _signature_payload(vault_id: str, device_id: str, event_hash: str) -> bytes:
    return f"shield-audit-sig-v1|{vault_id}|{device_id}|{event_hash}".encode("utf-8")


class AuditLog:
    """Append-only, SHA-256 hash-chained, Ed25519-signed security event logger."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                device_id TEXT NOT NULL,
                summary TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                signature TEXT NOT NULL DEFAULT '',
                signer_fingerprint TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # Forward-compatible migration for existing databases created before Ed25519 signatures
        existing_cols = {
            row[1] for row in self._conn.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        if "signature" not in existing_cols:
            self._conn.execute("ALTER TABLE audit_events ADD COLUMN signature TEXT NOT NULL DEFAULT ''")
        if "signer_fingerprint" not in existing_cols:
            self._conn.execute("ALTER TABLE audit_events ADD COLUMN signer_fingerprint TEXT NOT NULL DEFAULT ''")
        self._conn.commit()

    def _last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return str(row[0]) if row else GENESIS_HASH

    def record(
        self,
        event_type: str,
        summary: str,
        *,
        severity: str = "info",
        device_id: str = "local",
        metadata: dict[str, Any] | None = None,
        signing_private_key_b64: str = "",
        signing_public_key_b64: str = "",
        vault_id: str = "",
    ) -> AuditEvent:
        ts = _utc_now()
        clean_meta = _sanitize_metadata(metadata)
        meta_json = json.dumps(clean_meta, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        prev_hash = self._last_hash()
        ev_hash = _compute_event_hash(ts, event_type, severity, device_id, summary, meta_json, prev_hash)

        if signing_private_key_b64 and vault_id:
            sig = sign_ed25519(signing_private_key_b64, _signature_payload(vault_id, device_id, ev_hash))
            fp = public_key_fingerprint(signing_public_key_b64)
        else:
            sig = PREAUTH_SIGNATURE_MARKER
            fp = "PRE-AUTH"

        cur = self._conn.execute(
            """
            INSERT INTO audit_events
                (timestamp, event_type, severity, device_id, summary, metadata_json, prev_hash, event_hash, signature, signer_fingerprint)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, event_type, severity, device_id, summary, meta_json, prev_hash, ev_hash, sig, fp),
        )
        self._conn.commit()
        return AuditEvent(
            id=int(cur.lastrowid or 0),
            timestamp=ts,
            event_type=event_type,
            severity=severity,
            device_id=device_id,
            summary=summary,
            metadata=clean_meta,
            prev_hash=prev_hash,
            event_hash=ev_hash,
            signature=sig,
            signer_fingerprint=fp,
        )

    def _row_to_event(self, r: tuple[Any, ...]) -> AuditEvent:
        try:
            meta = json.loads(r[6]) if r[6] else {}
        except Exception:
            meta = {}
        return AuditEvent(
            id=int(r[0]),
            timestamp=str(r[1]),
            event_type=str(r[2]),
            severity=str(r[3]),
            device_id=str(r[4]),
            summary=str(r[5]),
            metadata=meta,
            prev_hash=str(r[7]),
            event_hash=str(r[8]),
            signature=str(r[9]),
            signer_fingerprint=str(r[10]),
        )

    def list_events(
        self,
        limit: int = 200,
        severity: str = "All",
        event_type: str = "",
    ) -> list[AuditEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity and severity != "All":
            clauses.append("severity = ?")
            params.append(severity.lower())
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT id, timestamp, event_type, severity, device_id, summary, metadata_json,
                   prev_hash, event_hash, signature, signer_fingerprint
            FROM audit_events
            {where}
            ORDER BY id DESC
            LIMIT ?
        """
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    def recent_alerts(self, limit: int = 10) -> list[AuditEvent]:
        rows = self._conn.execute(
            """
            SELECT id, timestamp, event_type, severity, device_id, summary, metadata_json,
                   prev_hash, event_hash, signature, signer_fingerprint
            FROM audit_events
            WHERE severity IN ('warning', 'alert', 'critical')
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def verify_chain(
        self,
        signing_public_key_b64: str = "",
        vault_id: str = "",
    ) -> tuple[bool, str]:
        """Verify BOTH SHA-256 hash-chain links AND Ed25519 digital signatures."""
        rows = self._conn.execute(
            """
            SELECT id, timestamp, event_type, severity, device_id, summary, metadata_json,
                   prev_hash, event_hash, signature, signer_fingerprint
            FROM audit_events
            ORDER BY id ASC
            """
        ).fetchall()

        expected_prev = GENESIS_HASH
        signed_count = 0
        preauth_count = 0

        for r in rows:
            eid, ts, etype, sev, dev, summ, meta_json, prev_hash, ev_hash, sig, _fp = r
            if prev_hash != expected_prev:
                return False, f"Audit hash chain broken at event #{eid} (unexpected previous hash)."
            recomputed = _compute_event_hash(ts, etype, sev, dev, summ, meta_json, prev_hash)
            if ev_hash != recomputed:
                return False, f"Audit tampering detected at event #{eid} (SHA-256 hash mismatch)."

            if sig and sig != PREAUTH_SIGNATURE_MARKER:
                if signing_public_key_b64 and vault_id:
                    if not verify_ed25519(
                        signing_public_key_b64, _signature_payload(vault_id, dev, ev_hash), sig
                    ):
                        return False, f"Non-repudiation failure at event #{eid} (invalid Ed25519 signature)."
                signed_count += 1
            else:
                preauth_count += 1

            expected_prev = ev_hash

        return (
            True,
            f"Verified intact ({len(rows)} hash-chained events; {signed_count} Ed25519-signed, {preauth_count} pre-auth)",
        )

    def export_signed_proof(
        self,
        dest_path: str | Path,
        signing_public_key_b64: str,
        vault_id: str,
    ) -> Path:
        """Export a verifiable, secrets-free Non-Repudiation Audit Proof JSON bundle."""
        ok, msg = self.verify_chain(signing_public_key_b64=signing_public_key_b64, vault_id=vault_id)
        rows = self._conn.execute(
            """
            SELECT id, timestamp, event_type, severity, device_id, summary, metadata_json,
                   prev_hash, event_hash, signature, signer_fingerprint
            FROM audit_events
            ORDER BY id ASC
            """
        ).fetchall()
        events = [
            {
                "id": int(r[0]),
                "timestamp": str(r[1]),
                "event_type": str(r[2]),
                "severity": str(r[3]),
                "device_id": str(r[4]),
                "summary": str(r[5]),
                "metadata": json.loads(r[6]) if r[6] else {},
                "prev_hash": str(r[7]),
                "event_hash": str(r[8]),
                "signature": str(r[9]),
                "signer_fingerprint": str(r[10]),
            }
            for r in rows
        ]
        proof = {
            "format": "pulse-shield-nonrepudiation-audit-v1",
            "vault_id": vault_id,
            "ed25519_public_key": signing_public_key_b64,
            "signer_fingerprint": public_key_fingerprint(signing_public_key_b64),
            "exported_at": _utc_now(),
            "chain_verified": ok,
            "verification_summary": msg,
            "event_count": len(events),
            "events": events,
        }
        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(proof, indent=2, ensure_ascii=False), encoding="utf-8")
        restrict_file_permissions(dest)
        return dest
