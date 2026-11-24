"""Identity & Access Management (IAM): Failed-login rate limiting & Trusted Device Registry."""

from __future__ import annotations

import hashlib
import platform
import socket
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone


class RateLimitError(Exception):
    """Raised when login or MFA attempts are temporarily locked out due to brute-force protection."""

    def __init__(self, message: str, retry_after_seconds: int) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class DeviceRevokedError(Exception):
    """Raised when the current device has been explicitly revoked."""


@dataclass
class TrustedDevice:
    device_id: str
    name: str
    os_info: str
    first_seen: str
    last_seen: str
    status: str  # "trusted" | "revoked"
    is_current: bool = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def compute_local_device_info() -> tuple[str, str, str]:
    """Compute a deterministic local device ID (non-cryptographic identifier), hostname, and OS."""
    host = socket.gethostname() or "unknown-host"
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    node = str(uuid.getnode())
    raw_fp = f"shield-device:{host}:{platform.system()}:{node}".encode("utf-8")
    device_id = "DEV-" + hashlib.sha256(raw_fp).hexdigest()[:12].upper()
    return device_id, host, os_info


def _backoff_seconds(failed_attempts: int) -> int:
    """Progressive exponential-like lockout against brute-force attempts."""
    if failed_attempts < 3:
        return 0
    if failed_attempts == 3:
        return 5
    if failed_attempts == 4:
        return 15
    if failed_attempts == 5:
        return 30
    if failed_attempts == 6:
        return 60
    return 180


class IdentityAccessManager:
    """Manages brute-force rate limiting, failed-login tracking, and trusted device lifecycle."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self.current_device_id, self.current_device_name, self.current_os_info = compute_local_device_info()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_state (
                scope TEXT PRIMARY KEY,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                total_failures INTEGER NOT NULL DEFAULT 0,
                lockout_until REAL NOT NULL DEFAULT 0,
                last_failure_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trusted_devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                os_info TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'trusted'
            )
            """
        )
        for scope in ("master", "mfa"):
            self._conn.execute(
                "INSERT OR IGNORE INTO auth_state (scope) VALUES (?)",
                (scope,),
            )
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # Brute-Force Rate Limiting & Failed-Login Monitoring
    # ------------------------------------------------------------------ #

    def check_rate_limit(self, scope: str = "master") -> None:
        """Raise RateLimitError if the given auth scope is currently locked out."""
        row = self._conn.execute(
            "SELECT failed_attempts, lockout_until FROM auth_state WHERE scope = ?",
            (scope,),
        ).fetchone()
        if not row:
            return
        lockout_until = float(row[1])
        now = time.time()
        if lockout_until > now:
            remaining = max(1, int(round(lockout_until - now)))
            raise RateLimitError(
                f"Too many failed {scope} attempts. Please wait {remaining}s before trying again.",
                retry_after_seconds=remaining,
            )

    def record_failure(self, scope: str = "master") -> tuple[int, int]:
        """Increment failure counter and apply progressive lockout. Returns (consecutive_fails, lockout_secs)."""
        row = self._conn.execute(
            "SELECT failed_attempts, total_failures FROM auth_state WHERE scope = ?",
            (scope,),
        ).fetchone()
        failed = (int(row[0]) if row else 0) + 1
        total = (int(row[1]) if row else 0) + 1
        lockout_secs = _backoff_seconds(failed)
        lockout_until = time.time() + lockout_secs if lockout_secs > 0 else 0.0
        self._conn.execute(
            """
            UPDATE auth_state
            SET failed_attempts = ?, total_failures = ?, lockout_until = ?, last_failure_at = ?
            WHERE scope = ?
            """,
            (failed, total, lockout_until, _utc_now(), scope),
        )
        self._conn.commit()
        return failed, lockout_secs

    def record_success(self, scope: str = "master") -> None:
        self._conn.execute(
            "UPDATE auth_state SET failed_attempts = 0, lockout_until = 0 WHERE scope = ?",
            (scope,),
        )
        self._conn.commit()

    def get_auth_stats(self) -> dict[str, dict[str, object]]:
        rows = self._conn.execute(
            "SELECT scope, failed_attempts, total_failures, lockout_until, last_failure_at FROM auth_state"
        ).fetchall()
        now = time.time()
        stats: dict[str, dict[str, object]] = {}
        for scope, fails, total, lock_until, last_at in rows:
            stats[str(scope)] = {
                "consecutive_failures": int(fails),
                "total_failures": int(total),
                "locked_out_seconds": max(0, int(round(float(lock_until) - now))),
                "last_failure_at": str(last_at),
            }
        return stats

    # ------------------------------------------------------------------ #
    # Trusted Devices Registry & Revocation
    # ------------------------------------------------------------------ #

    def ensure_device_not_revoked(self) -> None:
        """Reject immediately if the current device is already explicitly revoked (does not auto-register)."""
        row = self._conn.execute(
            "SELECT device_id, name, status FROM trusted_devices WHERE device_id = ?",
            (self.current_device_id,),
        ).fetchone()
        if row is not None and str(row[2]) == "revoked":
            raise DeviceRevokedError(
                f"Device '{row[1]}' ({row[0]}) has been revoked and cannot unlock this vault."
            )

    def check_or_register_current_device(self) -> tuple[TrustedDevice, bool]:
        """Verify current device is not revoked and register/touch it AFTER authentication succeeds.

        Returns (device, is_new_device). Raises DeviceRevokedError if revoked.
        """
        now = _utc_now()
        row = self._conn.execute(
            "SELECT device_id, name, os_info, first_seen, last_seen, status FROM trusted_devices WHERE device_id = ?",
            (self.current_device_id,),
        ).fetchone()

        if row is None:
            self._conn.execute(
                """
                INSERT INTO trusted_devices (device_id, name, os_info, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, 'trusted')
                """,
                (self.current_device_id, self.current_device_name, self.current_os_info, now, now),
            )
            self._conn.commit()
            return (
                TrustedDevice(
                    device_id=self.current_device_id,
                    name=self.current_device_name,
                    os_info=self.current_os_info,
                    first_seen=now,
                    last_seen=now,
                    status="trusted",
                    is_current=True,
                ),
                True,
            )

        status = str(row[5])
        if status == "revoked":
            raise DeviceRevokedError(
                f"Device '{row[1]}' ({row[0]}) has been revoked and cannot unlock this vault."
            )

        self._conn.execute(
            "UPDATE trusted_devices SET last_seen = ?, name = ?, os_info = ? WHERE device_id = ?",
            (now, self.current_device_name, self.current_os_info, self.current_device_id),
        )
        self._conn.commit()
        return (
            TrustedDevice(
                device_id=str(row[0]),
                name=self.current_device_name,
                os_info=self.current_os_info,
                first_seen=str(row[3]),
                last_seen=now,
                status=status,
                is_current=True,
            ),
            False,
        )

    def list_devices(self) -> list[TrustedDevice]:
        rows = self._conn.execute(
            "SELECT device_id, name, os_info, first_seen, last_seen, status FROM trusted_devices ORDER BY last_seen DESC"
        ).fetchall()
        return [
            TrustedDevice(
                device_id=str(r[0]),
                name=str(r[1]),
                os_info=str(r[2]),
                first_seen=str(r[3]),
                last_seen=str(r[4]),
                status=str(r[5]),
                is_current=(str(r[0]) == self.current_device_id),
            )
            for r in rows
        ]

    def register_device(self, name: str, os_info: str = "External / Manual Device") -> TrustedDevice:
        now = _utc_now()
        dev_id = "DEV-" + uuid.uuid4().hex[:12].upper()
        self._conn.execute(
            """
            INSERT INTO trusted_devices (device_id, name, os_info, first_seen, last_seen, status)
            VALUES (?, ?, ?, ?, ?, 'trusted')
            """,
            (dev_id, name.strip() or "Trusted Device", os_info.strip(), now, now),
        )
        self._conn.commit()
        return TrustedDevice(
            device_id=dev_id,
            name=name.strip() or "Trusted Device",
            os_info=os_info.strip(),
            first_seen=now,
            last_seen=now,
            status="trusted",
            is_current=False,
        )

    def set_device_status(self, device_id: str, status: str) -> bool:
        if status not in ("trusted", "revoked"):
            raise ValueError("Device status must be 'trusted' or 'revoked'.")
        cur = self._conn.execute(
            "UPDATE trusted_devices SET status = ? WHERE device_id = ?",
            (status, device_id),
        )
        self._conn.commit()
        return cur.rowcount > 0
