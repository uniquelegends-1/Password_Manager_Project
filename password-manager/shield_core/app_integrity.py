"""Application Integrity Verification — detects unauthorized modification or injection of critical files."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_FILENAME = "app_manifest.json"
MANIFEST_VERSION = 1

CRITICAL_ROOT_FILES = ("app.py", "dialogs.py", "vault.py", "requirements.txt")


@dataclass
class AppIntegrityResult:
    valid: bool
    checked_count: int
    modified_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    unexpected_files: list[str] = field(default_factory=list)
    message: str = ""


def compute_file_sha256(path: Path) -> str:
    """Compute exact SHA-256 hex digest of a file's raw bytes."""
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def discover_critical_files(app_dir: Path) -> list[Path]:
    """Return sorted list of critical application source & dependency files to monitor."""
    targets: list[Path] = []
    for name in CRITICAL_ROOT_FILES:
        p = app_dir / name
        if p.is_file():
            targets.append(p)
    core_dir = app_dir / "shield_core"
    if core_dir.is_dir():
        for p in sorted(core_dir.glob("*.py")):
            targets.append(p)
    return sorted(targets, key=lambda p: p.relative_to(app_dir).as_posix())


def _canonical_files_hash(files_map: dict[str, str]) -> str:
    canonical = json.dumps(files_map, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def generate_app_manifest(app_dir: str | Path, output_path: str | Path | None = None) -> Path:
    """Generate a SHA-256 integrity manifest covering all critical application files."""
    root = Path(app_dir).resolve()
    out = Path(output_path) if output_path else (root / MANIFEST_FILENAME)

    files_map: dict[str, str] = {}
    for p in discover_critical_files(root):
        rel = p.relative_to(root).as_posix()
        files_map[rel] = compute_file_sha256(p)

    manifest: dict[str, Any] = {
        "format": "pulse-shield-app-manifest-v1",
        "version": MANIFEST_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "file_count": len(files_map),
        "files": files_map,
        "manifest_sha256": _canonical_files_hash(files_map),
    }
    out.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return out


def verify_app_integrity(
    app_dir: str | Path, manifest_path: str | Path | None = None
) -> AppIntegrityResult:
    """Verify every critical application file against the recorded SHA-256 manifest.

    Detects modified files, deleted files, manifest corruption, and unexpected injected `.py` files in shield_core/.
    """
    root = Path(app_dir).resolve()
    mpath = Path(manifest_path) if manifest_path else (root / MANIFEST_FILENAME)

    if not mpath.is_file():
        return AppIntegrityResult(
            valid=False,
            checked_count=0,
            message=f"Application integrity manifest missing ({mpath.name}). Regenerate after verifying source.",
        )

    try:
        data = json.loads(mpath.read_text(encoding="utf-8"))
        if data.get("format") != "pulse-shield-app-manifest-v1":
            raise ValueError("Unsupported manifest format.")
        files_map = data["files"]
        if not isinstance(files_map, dict) or not files_map:
            raise ValueError("Manifest file list is empty or malformed.")
        expected_meta_hash = str(data.get("manifest_sha256", ""))
        if expected_meta_hash != _canonical_files_hash(files_map):
            return AppIntegrityResult(
                valid=False,
                checked_count=0,
                message="Manifest self-checksum mismatch (app_manifest.json was modified or corrupted).",
            )
    except Exception as exc:
        return AppIntegrityResult(
            valid=False,
            checked_count=0,
            message=f"Failed to parse integrity manifest: {exc}",
        )

    modified: list[str] = []
    missing: list[str] = []

    for rel, expected_sha in files_map.items():
        target = (root / rel).resolve()
        # Ensure manifest path cannot escape app_dir
        try:
            target.relative_to(root)
        except ValueError:
            modified.append(rel)
            continue
        if not target.is_file():
            missing.append(rel)
            continue
        actual_sha = compute_file_sha256(target)
        if actual_sha != expected_sha:
            modified.append(rel)

    # Detect unexpected injected Python files inside shield_core/
    current_rel = {p.relative_to(root).as_posix() for p in discover_critical_files(root)}
    unexpected = sorted(current_rel - set(files_map.keys()))

    if modified or missing or unexpected:
        parts: list[str] = []
        if modified:
            parts.append(f"modified: {', '.join(modified)}")
        if missing:
            parts.append(f"missing: {', '.join(missing)}")
        if unexpected:
            parts.append(f"unexpected: {', '.join(unexpected)}")
        return AppIntegrityResult(
            valid=False,
            checked_count=len(files_map),
            modified_files=modified,
            missing_files=missing,
            unexpected_files=unexpected,
            message="APPLICATION INTEGRITY FAILURE — " + " | ".join(parts),
        )

    return AppIntegrityResult(
        valid=True,
        checked_count=len(files_map),
        message=f"Application integrity verified ({len(files_map)} critical files match SHA-256 manifest).",
    )
