"""Creates a native Windows Desktop & Start Menu App shortcut for S.H.I.E.L.D. Vault (no PowerShell window)."""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
ICON_PATH = APP_DIR / "shield_icon.ico"
APP_SCRIPT = APP_DIR / "app.py"
SHORTCUT_NAME = "S.H.I.E.L.D. Vault.lnk"


def _render_shield_png(size: int) -> bytes:
    """Render a crisp RGBA PNG shield + keyhole icon using pure Python stdlib."""
    pixels = bytearray(size * size * 4)

    def set_px(x: int, y: int, r: int, g: int, b: int, a: int) -> None:
        if 0 <= x < size and 0 <= y < size:
            idx = (y * size + x) * 4
            pixels[idx] = r
            pixels[idx + 1] = g
            pixels[idx + 2] = b
            pixels[idx + 3] = a

    cx = (size - 1) / 2.0
    for y in range(size):
        ny = y / float(size - 1)  # 0..1 top to bottom
        for x in range(size):
            nx = (x - cx) / (size * 0.45)  # -1..1 approx
            ax = abs(nx)

            # Shield silhouette curve
            if ny < 0.08 or ny > 0.94:
                continue
            if ny <= 0.48:
                # Top arched crown & straight sides
                top_cut = 0.08 + 0.07 * (ax**2)
                if ny < top_cut or ax > 0.88:
                    continue
                edge_dist = min(0.88 - ax, (ny - top_cut) * 4.0)
            else:
                # Tapered lower shield point
                t = (ny - 0.48) / 0.46  # 0..1
                max_x = 0.88 * (1.0 - (t**1.45))
                if ax > max_x:
                    continue
                edge_dist = max_x - ax

            # Border vs interior gradient
            if edge_dist < 0.09:
                r, g, b = 59, 130, 246  # Bright accent blue border (#3b82f6)
            else:
                # Deep slate-navy vertical gradient
                r = int(15 + 16 * (1.0 - ny))
                g = int(28 + 38 * (1.0 - ny))
                b = int(58 + 70 * (1.0 - ny))

            # Subtle inner highlight on left half
            if nx < 0 and edge_dist >= 0.09:
                r = min(255, r + 10)
                g = min(255, g + 16)
                b = min(255, b + 24)

            # White lock / keyhole emblem in center
            dx = (x - cx) / float(size)
            dy_head = (y - size * 0.44) / float(size)
            in_circle = (dx * dx + dy_head * dy_head) <= (0.095**2)
            in_stem = (abs(dx) <= 0.048) and (0.47 <= ny <= 0.67)
            if in_circle or in_stem:
                r, g, b = 248, 250, 252

            set_px(x, y, r, g, b, 255)

    # Encode minimal valid PNG (RGBA, 8-bit)
    raw_rows = bytearray()
    stride = size * 4
    for y in range(size):
        raw_rows.append(0)  # filter type 0
        raw_rows.extend(pixels[y * stride : (y + 1) * stride])

    def chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw_rows), level=9))
        + chunk(b"IEND", b"")
    )


def create_ico(dest: Path) -> Path:
    """Write a multi-resolution Windows .ico file (32x32, 64x64, 128x128)."""
    sizes = (32, 64, 128)
    images = [_render_shield_png(s) for s in sizes]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = bytearray()
    for s, png in zip(sizes, images):
        w = s if s < 256 else 0
        entries.extend(struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(png), offset))
        offset += len(png)
    dest.write_bytes(header + bytes(entries) + b"".join(images))
    return dest


def _create_windows_shortcut(lnk_path: Path, target_exe: Path, arguments: str, work_dir: Path, icon: Path) -> None:
    """Create a native Windows .lnk shortcut via WScript.Shell (zero PowerShell window when launched)."""
    def esc(s: str) -> str:
        return s.replace("'", "''")

    ps_script = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$sc = $ws.CreateShortcut('{esc(str(lnk_path))}'); "
        f"$sc.TargetPath = '{esc(str(target_exe))}'; "
        f"$sc.Arguments = '{esc(arguments)}'; "
        f"$sc.WorkingDirectory = '{esc(str(work_dir))}'; "
        f"$sc.IconLocation = '{esc(str(icon))},0'; "
        "$sc.Description = 'P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T. Zero-Trust Password Manager'; "
        "$sc.Save()"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        check=True,
        capture_output=True,
        text=True,
    )


def install_app() -> list[Path]:
    create_ico(ICON_PATH)
    py_exe = Path(sys.executable)
    pythonw = py_exe.with_name("pythonw.exe")
    launcher = pythonw if pythonw.is_file() else py_exe
    args = f'"{APP_SCRIPT}"'

    created: list[Path] = []
    destinations = [APP_DIR / SHORTCUT_NAME]

    start_menu = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    if start_menu.is_dir():
        destinations.append(start_menu / SHORTCUT_NAME)

    desktop = Path.home() / "Desktop"
    if desktop.is_dir():
        destinations.append(desktop / SHORTCUT_NAME)

    for dest in destinations:
        _create_windows_shortcut(dest, launcher, args, APP_DIR, ICON_PATH)
        created.append(dest)
    return created


if __name__ == "__main__":
    paths = install_app()
    for p in paths:
        sys.stdout.write(f"Created app shortcut: {p}\n")
