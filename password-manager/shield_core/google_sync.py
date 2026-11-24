"""Consent-gated Google Password Manager CSV import/export & Google Drive E2EE sync helpers."""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shield_core.vault_engine import VaultEntry

GOOGLE_PASSWORDS_URL = "https://passwords.google.com"
GOOGLE_CHECKUP_URL = "https://passwords.google.com/checkup"
GOOGLE_SECURITY_URL = "https://myaccount.google.com/security"


@dataclass
class GoogleCsvItem:
    title: str
    url: str
    username: str
    password: str
    notes: str = ""


def parse_google_passwords_csv(csv_path: str | Path) -> tuple[list[GoogleCsvItem], int]:
    path = Path(csv_path)
    items: list[GoogleCsvItem] = []
    skipped = 0

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV file has no header row.")

        field_map = {name.strip().lower(): name for name in reader.fieldnames if name}
        if "password" not in field_map and "username" not in field_map:
            raise ValueError(
                "This file does not look like a Google Password Manager export "
                "(expected columns: name, url, username, password, note)."
            )

        def get_col(row: dict[str, str], *candidates: str) -> str:
            for c in candidates:
                orig = field_map.get(c)
                if orig is not None and row.get(orig):
                    return row[orig].strip()
            return ""

        for row in reader:
            name = get_col(row, "name", "title", "service")
            url = get_col(row, "url", "website", "origin")
            username = get_col(row, "username", "login", "email")
            password = get_col(row, "password", "pass")
            note = get_col(row, "note", "notes", "comment")

            if not name and url:
                name = url.replace("https://", "").replace("http://", "").split("/")[0]
            if not name and not username and not password:
                skipped += 1
                continue

            items.append(
                GoogleCsvItem(
                    title=name or "Imported Google Account",
                    url=url,
                    username=username,
                    password=password,
                    notes=note,
                )
            )

    return items, skipped


def export_google_passwords_csv(entries: list[VaultEntry], dest_path: str | Path) -> Path:
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["name", "url", "username", "password", "note"])
        for entry in entries:
            writer.writerow([entry.title, entry.url, entry.username, entry.password, entry.notes])
    return dest


def secure_delete_file(file_path: str | Path) -> bool:
    """Overwrite a sensitive plaintext file with random bytes and zeros before unlinking."""
    path = Path(file_path)
    if not path.is_file():
        return False
    size = path.stat().st_size
    if size > 0:
        with path.open("r+b") as handle:
            handle.seek(0)
            handle.write(os.urandom(size))
            handle.flush()
            os.fsync(handle.fileno())
            handle.seek(0)
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    path.unlink()
    return True


def detect_google_drive_folders() -> list[Path]:
    candidates: list[Path] = []
    home = Path.home()
    for drive in ("G", "H", "I", "D", "E"):
        p = Path(f"{drive}:\\My Drive")
        if p.is_dir():
            candidates.append(p)
    for rel in ("Google Drive", "My Drive", "GoogleDrive"):
        p = home / rel
        if p.is_dir() and p not in candidates:
            candidates.append(p)
    return candidates
