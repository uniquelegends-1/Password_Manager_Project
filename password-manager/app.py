"""P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T. — Zero-Trust Local-First Desktop Password Vault."""

from __future__ import annotations

import ctypes
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from dialogs import (
    THEMES,
    ChangeMasterPasswordDialog,
    E2EESyncShareDialog,
    GoogleVaultDialog,
    MFASetupDialog,
    PasswordGeneratorDialog,
    RecoveryKitDialog,
    StrengthBar,
    VaultRecoveryDialog,
    prompt_adaptive_reauth,
)
from shield_core.adaptive_security import AdaptivePolicyConfig
from shield_core.app_integrity import verify_app_integrity
from shield_core.governance_ops import (
    IR_PHASES,
    IR_PLAYBOOKS,
    RECOVERY_WORKFLOWS,
    RiskRecord,
    SecurityPolicyConfig,
)
from shield_core.identity_access import DeviceRevokedError, RateLimitError
from shield_core.mfa import get_totp_code, normalize_totp_secret
from shield_core.security_audit import (
    VaultAuditReport,
    WebsiteScanResult,
    audit_vault,
    check_hibp_pwned,
    match_known_site_advisory,
    scan_website_security,
)
from shield_core.vault_engine import (
    CATEGORIES,
    ENTRY_TYPES,
    InvalidMFACodeError,
    InvalidPasswordError,
    ShieldVault,
    VaultEntry,
    VaultError,
)

APP_TITLE = "P.U.L.S.E. S.H.I.E.L.D. — V.A.U.L.T."
DEFAULT_VAULT_PATH = Path(__file__).resolve().parent / "shield_vault.db"
APP_ICON_PATH = Path(__file__).resolve().parent / "shield_icon.ico"


def _enable_windows_dpi_awareness() -> None:
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PULSE.SHIELD.Vault.1")
        except Exception:
            pass
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


class ShieldVaultApp(tk.Tk):
    """Main S.H.I.E.L.D. / V.A.U.L.T. Tkinter Desktop Application."""

    def __init__(self, vault_path: Path = DEFAULT_VAULT_PATH) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1220x780")
        self.minsize(1020, 660)
        if APP_ICON_PATH.is_file():
            try:
                self.iconbitmap(default=str(APP_ICON_PATH))
            except tk.TclError:
                pass

        self._theme_name = "dark"
        self._colors = THEMES[self._theme_name]
        self.configure(bg=self._colors["bg"])

        self._vault = ShieldVault(vault_path)
        self._active_tab = "dashboard"

        # Credential editor state
        self._selected_entry_id: str | None = None
        self._is_creating_new = False
        self._password_visible = False
        self._totp_secret_visible = False
        self._temp_reveal_timer_id: str | None = None

        # Cached opt-in health scan state (session only)
        self._hibp_counts: dict[str, int] = {}
        self._web_scans: dict[str, WebsiteScanResult] = {}
        self._health_scanning = False

        # Clipboard, auto-lock & live TOTP timers
        self._clipboard_secret: str | None = None
        self._clipboard_timer_id: str | None = None
        self._clipboard_remaining = 0
        self._auto_lock_timer_id: str | None = None
        self._status_clear_id: str | None = None
        self._totp_tick_id: str | None = None

        self._configure_styles()

        self._container = tk.Frame(self, bg=self._colors["bg"])
        self._container.pack(fill="both", expand=True)

        # Bottom Status Bar
        self._status_bar = tk.Frame(self, bg=self._colors["input"], height=28)
        self._status_bar.pack(fill="x", side="bottom")
        self._status_var = tk.StringVar(value="Locked — Zero-Trust Local Mode")
        self._status_label = tk.Label(
            self._status_bar,
            textvariable=self._status_var,
            bg=self._colors["input"],
            fg=self._colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            padx=12,
            pady=4,
        )
        self._status_label.pack(side="left", fill="x", expand=True)
        self._vault_path_status = tk.Label(
            self._status_bar,
            text=str(self._vault.path),
            bg=self._colors["input"],
            fg=self._colors["muted"],
            font=("Segoe UI", 8),
            anchor="e",
            padx=12,
        )
        self._vault_path_status.pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._app_integrity = verify_app_integrity(Path(__file__).resolve().parent)
        self._show_lock_screen(
            banner_message="" if self._app_integrity.valid else self._app_integrity.message
        )

    # ------------------------------------------------------------------ #
    # Theme & ttk Styling
    # ------------------------------------------------------------------ #

    def _configure_styles(self) -> None:
        c = self._colors
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "TButton",
            background=c["surface_alt"],
            foreground=c["text"],
            borderwidth=0,
            focusthickness=0,
            padding=(10, 6),
            font=("Segoe UI", 9),
        )
        style.map(
            "TButton",
            background=[("active", c["border"]), ("pressed", c["border"])],
            foreground=[("disabled", c["muted"])],
        )

        style.configure(
            "Accent.TButton",
            background=c["accent"],
            foreground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padding=(12, 6),
        )
        style.map(
            "Accent.TButton",
            background=[("active", c["accent_hover"]), ("pressed", c["accent_hover"])],
        )

        style.configure(
            "Danger.TButton",
            background=c["danger"],
            foreground="#ffffff",
            font=("Segoe UI", 9),
            padding=(12, 6),
        )
        style.map(
            "Danger.TButton",
            background=[("active", c["danger_hover"]), ("pressed", c["danger_hover"])],
        )

        style.configure("TNotebook", background=c["surface"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=c["surface_alt"],
            foreground=c["muted"],
            padding=(10, 6),
            font=("Segoe UI", 9),
        )
        style.map("TNotebook.Tab", background=[("selected", c["accent"])], foreground=[("selected", "#ffffff")])

        style.configure(
            "TCombobox",
            fieldbackground=c["input"],
            background=c["surface_alt"],
            foreground=c["text"],
            arrowcolor=c["text"],
            borderwidth=0,
            padding=5,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", c["input"])],
            foreground=[("readonly", c["text"])],
            selectbackground=[("readonly", c["input"])],
            selectforeground=[("readonly", c["text"])],
        )

        style.configure(
            "Vault.Treeview",
            background=c["surface"],
            fieldbackground=c["surface"],
            foreground=c["text"],
            rowheight=32,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Vault.Treeview.Heading",
            background=c["surface_alt"],
            foreground=c["muted"],
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padding=(8, 6),
        )
        style.map("Vault.Treeview", background=[("selected", c["select"])], foreground=[("selected", "#ffffff")])
        style.map("Vault.Treeview.Heading", background=[("active", c["border"])])

        style.configure(
            "Vertical.TScrollbar",
            background=c["surface_alt"],
            troughcolor=c["surface"],
            borderwidth=0,
            arrowcolor=c["muted"],
        )

    def _toggle_theme(self) -> None:
        self._theme_name = "light" if self._theme_name == "dark" else "dark"
        self._colors = THEMES[self._theme_name]
        self.configure(bg=self._colors["bg"])
        self._container.configure(bg=self._colors["bg"])
        self._status_bar.configure(bg=self._colors["input"])
        self._status_label.configure(bg=self._colors["input"], fg=self._colors["muted"])
        self._vault_path_status.configure(bg=self._colors["input"], fg=self._colors["muted"])
        self._configure_styles()
        if self._vault.is_unlocked:
            self._show_main_workspace(tab=self._active_tab)
        else:
            self._show_lock_screen()

    # ------------------------------------------------------------------ #
    # Lifecycle, Clipboard & Auto-Lock
    # ------------------------------------------------------------------ #

    def _cancel_timers(self) -> None:
        for attr in ("_totp_tick_id", "_temp_reveal_timer_id"):
            tid = getattr(self, attr)
            if tid is not None:
                self.after_cancel(tid)
                setattr(self, attr, None)

    def _clear_container(self) -> None:
        self._cancel_timers()
        for child in self._container.winfo_children():
            child.destroy()

    def _set_status(self, message: str, clear_after_ms: int | None = 5000) -> None:
        if self._status_clear_id is not None:
            self.after_cancel(self._status_clear_id)
            self._status_clear_id = None
        self._status_var.set(message)
        if clear_after_ms and self._vault.is_unlocked:
            mins = self._vault.adaptive_config.auto_lock_seconds // 60
            self._status_clear_id = self.after(
                clear_after_ms,
                lambda: self._status_var.set(
                    f"S.H.I.E.L.D. Unlocked (Argon2id + AES-256-GCM Per-Record DEK) • {self._vault.count()} entries • Auto-locks in {mins}m"
                )
                if self._vault.is_unlocked
                else None,
            )

    def _copy_to_clipboard(self, text: str, label: str = "Value", is_secret: bool = False) -> None:
        if not text:
            self._set_status(f"Nothing to copy for {label}.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        if is_secret:
            timeout = self._vault.adaptive_config.clipboard_clear_seconds if self._vault.is_unlocked else 20
            self._clipboard_secret = text
            self._clipboard_remaining = timeout
            if self._clipboard_timer_id is not None:
                self.after_cancel(self._clipboard_timer_id)
            self._tick_clipboard_countdown(label)
        else:
            self._set_status(f"{label} copied to clipboard.")

    def _tick_clipboard_countdown(self, label: str) -> None:
        if self._clipboard_remaining <= 0:
            self._clear_secret_clipboard()
            return
        self._set_status(f"{label} copied — clipboard auto-clears in {self._clipboard_remaining}s", clear_after_ms=None)
        self._clipboard_remaining -= 1
        self._clipboard_timer_id = self.after(1000, lambda: self._tick_clipboard_countdown(label))

    def _clear_secret_clipboard(self) -> None:
        if self._clipboard_timer_id is not None:
            self.after_cancel(self._clipboard_timer_id)
            self._clipboard_timer_id = None
        if self._clipboard_secret is not None:
            try:
                current = self.clipboard_get()
            except tk.TclError:
                current = None
            if current == self._clipboard_secret:
                self.clipboard_clear()
            self._clipboard_secret = None
            if self._vault.is_unlocked:
                self._set_status("Clipboard cleared automatically.")

    def _reset_auto_lock(self, _event: tk.Event | None = None) -> None:
        if not self._vault.is_unlocked:
            return
        if self._auto_lock_timer_id is not None:
            self.after_cancel(self._auto_lock_timer_id)
        timeout_ms = self._vault.adaptive_config.auto_lock_seconds * 1000
        self._auto_lock_timer_id = self.after(
            timeout_ms, lambda: self._lock_vault("Vault auto-locked due to inactivity.") if self._vault.is_unlocked else None
        )

    def _bind_activity(self) -> None:
        for seq in ("<Any-KeyPress>", "<ButtonPress>", "<Motion>"):
            self.bind_all(seq, self._reset_auto_lock, add="+")

    def _unbind_activity(self) -> None:
        for seq in ("<Any-KeyPress>", "<ButtonPress>", "<Motion>"):
            self.unbind_all(seq)

    def _on_close(self) -> None:
        self._clear_secret_clipboard()
        self._vault.close()
        self.destroy()

    # ------------------------------------------------------------------ #
    # Lock / Create / Recovery / Stage-2 MFA Screens
    # ------------------------------------------------------------------ #

    def _show_lock_screen(self, banner_message: str = "") -> None:
        c = self._colors
        self._unbind_activity()
        if self._auto_lock_timer_id is not None:
            self.after_cancel(self._auto_lock_timer_id)
            self._auto_lock_timer_id = None

        self._clear_container()
        self._selected_entry_id = None
        self._is_creating_new = False
        self._vault_path_status.configure(text=str(self._vault.path))
        self._set_status(banner_message or "Locked — Zero-Trust Local Mode", clear_after_ms=None)

        for seq in ("<Control-n>", "<Control-f>", "<Control-l>", "<Control-s>"):
            self.unbind(seq)

        wrapper = tk.Frame(self._container, bg=c["bg"])
        wrapper.place(relx=0.5, rely=0.48, anchor="center")

        card = tk.Frame(wrapper, bg=c["surface"], padx=36, pady=30)
        card.pack()

        is_existing = self._vault.exists
        heading = "Unlock S.H.I.E.L.D. Vault" if is_existing else "Initialize Zero-Trust Vault"
        subtitle = (
            "Argon2id + AES-256-GCM (Per-Record DEKs). Your master password is never stored."
            if is_existing
            else "Create your P.U.L.S.E. S.H.I.E.L.D. SQLite vault. Zero-reset architecture: save your Emergency Recovery Kit offline."
        )

        hdr_row = tk.Frame(card, bg=c["surface"])
        hdr_row.pack(fill="x")
        tk.Label(
            hdr_row, text="P.U.L.S.E.  •  S.H.I.E.L.D. / V.A.U.L.T.", bg=c["surface"], fg=c["accent"], font=("Segoe UI", 10, "bold")
        ).pack(side="left")
        ttk.Button(
            hdr_row,
            text="Light Mode" if self._theme_name == "dark" else "Dark Mode",
            command=self._toggle_theme,
        ).pack(side="right")

        tk.Label(card, text=heading, bg=c["surface"], fg=c["text"], font=("Segoe UI", 18, "bold")).pack(
            anchor="w", pady=(6, 4)
        )
        tk.Label(
            card, text=subtitle, bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9), wraplength=420, justify="left"
        ).pack(anchor="w", pady=(0, 14))

        file_row = tk.Frame(card, bg=c["input"], padx=10, pady=7)
        file_row.pack(fill="x", pady=(0, 14))
        tk.Label(file_row, text=f"Database: {self._vault.path.name}", bg=c["input"], fg=c["text"], font=("Segoe UI", 9)).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(file_row, text="Open .db...", command=self._choose_existing_vault).pack(side="right", padx=(6, 0))
        ttk.Button(file_row, text="New .db...", command=self._choose_new_vault).pack(side="right")

        self._master_var = tk.StringVar()
        self._confirm_var = tk.StringVar()
        self._lock_show_var = tk.BooleanVar(value=False)
        self._create_rec_kit_var = tk.BooleanVar(value=True)

        tk.Label(card, text="Master Password / Passphrase", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 4)
        )
        pwd_entry = tk.Entry(
            card,
            textvariable=self._master_var,
            show="•",
            bg=c["input"],
            fg=c["text"],
            insertbackground=c["text"],
            relief="flat",
            font=("Segoe UI", 12),
            width=38,
        )
        pwd_entry.pack(fill="x", ipady=8, pady=(0, 8))
        pwd_entry.focus_set()

        confirm_entry: tk.Entry | None = None
        if not is_existing:
            bar = StrengthBar(card, colors=c)
            bar.pack(fill="x", pady=(0, 10))
            self._master_var.trace_add("write", lambda *_: bar.update_password(self._master_var.get()))

            tk.Label(card, text="Confirm Master Password (min 8 chars)", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(
                anchor="w", pady=(0, 4)
            )
            confirm_entry = tk.Entry(
                card,
                textvariable=self._confirm_var,
                show="•",
                bg=c["input"],
                fg=c["text"],
                insertbackground=c["text"],
                relief="flat",
                font=("Segoe UI", 12),
            )
            confirm_entry.pack(fill="x", ipady=8, pady=(0, 8))

            tk.Checkbutton(
                card,
                text="Generate Zero-Reset Emergency Recovery Kit now (Recommended)",
                variable=self._create_rec_kit_var,
                bg=c["surface"],
                fg=c["text"],
                selectcolor=c["input"],
                activebackground=c["surface"],
                activeforeground=c["text"],
                font=("Segoe UI", 9),
            ).pack(anchor="w", pady=(0, 4))

        def toggle_vis() -> None:
            ch = "" if self._lock_show_var.get() else "•"
            pwd_entry.configure(show=ch)
            if confirm_entry is not None:
                confirm_entry.configure(show=ch)

        tk.Checkbutton(
            card,
            text="Show master password",
            variable=self._lock_show_var,
            command=toggle_vis,
            bg=c["surface"],
            fg=c["muted"],
            selectcolor=c["input"],
            activebackground=c["surface"],
            activeforeground=c["text"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(0, 8))

        self._lock_error = tk.Label(
            card,
            text=banner_message,
            bg=c["surface"],
            fg=c["warning"] if "locked" in banner_message.lower() else c["danger"],
            font=("Segoe UI", 9),
            wraplength=420,
            justify="left",
        )
        self._lock_error.pack(anchor="w", pady=(0, 10))

        action_label = "Unlock Vault" if is_existing else "Create Zero-Trust Vault"
        action_fn = self._handle_unlock if is_existing else self._handle_create
        ttk.Button(card, text=action_label, style="Accent.TButton", command=action_fn).pack(fill="x", ipady=4)

        if is_existing:
            rec_row = tk.Frame(card, bg=c["surface"])
            rec_row.pack(fill="x", pady=(10, 0))
            ttk.Button(
                rec_row,
                text="Recover Vault with Emergency Recovery Key...",
                command=self._open_recovery_dialog,
            ).pack(fill="x")

        pwd_entry.bind("<Return>", lambda _e: action_fn())
        if confirm_entry is not None:
            confirm_entry.bind("<Return>", lambda _e: action_fn())

    def _show_mfa_challenge_screen(self) -> None:
        c = self._colors
        self._clear_container()
        self._set_status("Stage-2 MFA verification required", clear_after_ms=None)

        wrapper = tk.Frame(self._container, bg=c["bg"])
        wrapper.place(relx=0.5, rely=0.46, anchor="center")
        card = tk.Frame(wrapper, bg=c["surface"], padx=34, pady=30)
        card.pack()

        tk.Label(card, text="S.H.I.E.L.D.  •  MULTI-FACTOR AUTHENTICATION", bg=c["surface"], fg=c["accent"], font=("Segoe UI", 9, "bold")).pack(
            anchor="w"
        )
        tk.Label(card, text="Enter Authenticator Code", bg=c["surface"], fg=c["text"], font=("Segoe UI", 17, "bold")).pack(
            anchor="w", pady=(4, 6)
        )
        tk.Label(
            card,
            text="Enter the 6-digit TOTP code from your authenticator app (anti-replay protected) or a one-time recovery code.",
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
            wraplength=390,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))

        self._mfa_code_var = tk.StringVar()
        ent = tk.Entry(
            card,
            textvariable=self._mfa_code_var,
            bg=c["input"],
            fg=c["text"],
            insertbackground=c["text"],
            relief="flat",
            font=("Consolas", 16),
            justify="center",
            width=18,
        )
        ent.pack(fill="x", ipady=10, pady=(0, 10))
        ent.focus_set()

        self._mfa_error = tk.Label(card, text="", bg=c["surface"], fg=c["danger"], font=("Segoe UI", 9), wraplength=390)
        self._mfa_error.pack(anchor="w", pady=(0, 12))

        btns = tk.Frame(card, bg=c["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=lambda: self._lock_vault("Unlock cancelled.")).pack(side="left")
        ttk.Button(btns, text="Verify & Unlock", style="Accent.TButton", command=self._handle_mfa_submit).pack(side="right")
        ent.bind("<Return>", lambda _e: self._handle_mfa_submit())

    def _choose_existing_vault(self) -> None:
        chosen = filedialog.askopenfilename(
            title="Open S.H.I.E.L.D. Vault Database",
            initialdir=str(self._vault.path.parent),
            filetypes=[("S.H.I.E.L.D. SQLite Vault", "*.db"), ("All Files", "*.*")],
        )
        if chosen:
            self._vault.close()
            self._vault = ShieldVault(Path(chosen))
            self._show_lock_screen()

    def _choose_new_vault(self) -> None:
        chosen = filedialog.asksaveasfilename(
            title="Create New S.H.I.E.L.D. Vault Database",
            initialdir=str(self._vault.path.parent),
            defaultextension=".db",
            initialfile="my_shield_vault.db",
            filetypes=[("S.H.I.E.L.D. SQLite Vault", "*.db")],
        )
        if chosen:
            path = Path(chosen)
            if path.exists():
                if not messagebox.askyesno("Overwrite Database?", f"Erase and recreate '{path.name}'?"):
                    return
                path.unlink()
            self._vault.close()
            self._vault = ShieldVault(path)
            self._show_lock_screen()

    def _open_recovery_dialog(self) -> None:
        if not self._vault.has_recovery_kit:
            messagebox.showwarning(
                "No Recovery Kit Configured",
                "This vault does not have an Emergency Recovery Kit configured.\n\n"
                "Under S.H.I.E.L.D.'s zero-reset architecture, there is no master-password reset without pre-generated recovery material.",
            )
            return
        VaultRecoveryDialog(
            self,
            self._vault,
            self._colors,
            on_recovered=lambda: (
                self._show_main_workspace(tab="dashboard"),
                self._set_status("Vault recovered via Emergency Recovery Key!"),
            ),
        )

    def _handle_create(self) -> None:
        pwd = self._master_var.get()
        conf = self._confirm_var.get()
        if len(pwd) < 8:
            self._lock_error.configure(text="Master password must be at least 8 characters.", fg=self._colors["danger"])
            return
        if pwd != conf:
            self._lock_error.configure(text="Passwords do not match.", fg=self._colors["danger"])
            return
        self._lock_error.configure(text="Deriving Argon2id master key...", fg=self._colors["muted"])
        self.update_idletasks()
        try:
            rec_key = self._vault.create(pwd, create_recovery_kit=self._create_rec_kit_var.get())
        except Exception as exc:
            self._lock_error.configure(text=f"Creation failed: {exc}", fg=self._colors["danger"])
            return
        finally:
            self._master_var.set("")
            self._confirm_var.set("")

        self._show_main_workspace(tab="dashboard")
        self._set_status("Zero-trust Argon2id SQLite vault initialized.")
        if rec_key:
            RecoveryKitDialog(
                self,
                rec_key,
                self._colors,
                on_copy_secret=lambda s, lbl: self._copy_to_clipboard(s, lbl, is_secret=True),
            )

    def _handle_unlock(self) -> None:
        pwd = self._master_var.get()
        if not pwd:
            self._lock_error.configure(text="Enter your master password.", fg=self._colors["danger"])
            return
        self._lock_error.configure(text="Deriving Argon2id key & verifying...", fg=self._colors["muted"])
        self.update_idletasks()
        try:
            unlocked = self._vault.unlock(pwd)
        except (RateLimitError, DeviceRevokedError) as exc:
            self._lock_error.configure(text=str(exc), fg=self._colors["danger"])
            self._master_var.set("")
            return
        except (InvalidPasswordError, VaultError) as exc:
            self._lock_error.configure(text=str(exc), fg=self._colors["danger"])
            self._master_var.set("")
            return
        finally:
            self._master_var.set("")

        if unlocked:
            self._show_main_workspace(tab="dashboard")
            self._set_status(f"S.H.I.E.L.D. Vault unlocked ({self._vault.count()} encrypted records).")
        else:
            self._show_mfa_challenge_screen()

    def _handle_mfa_submit(self) -> None:
        code = self._mfa_code_var.get().strip()
        if not code:
            self._mfa_error.configure(text="Enter a 6-digit TOTP or recovery code.")
            return
        try:
            used_totp = self._vault.complete_mfa(code)
        except (RateLimitError, InvalidMFACodeError) as exc:
            self._mfa_error.configure(text=str(exc))
            self._mfa_code_var.set("")
            return
        except VaultError as exc:
            self._lock_vault(str(exc))
            return

        self._show_main_workspace(tab="dashboard")
        msg = (
            f"Unlocked with MFA ({self._vault.count()} entries)."
            if used_totp
            else f"Unlocked via one-time recovery code ({self._vault.remaining_mfa_recovery_codes} left)."
        )
        self._set_status(msg)

    def _lock_vault(self, reason: str = "Vault locked. Encryption keys cleared from RAM.") -> None:
        self._clear_secret_clipboard()
        self._hibp_counts.clear()
        self._web_scans.clear()
        self._vault.lock()
        self._show_lock_screen(banner_message=reason)

    # ------------------------------------------------------------------ #
    # Main Sidebar Workspace Shell
    # ------------------------------------------------------------------ #

    def _show_main_workspace(self, tab: str = "dashboard") -> None:
        c = self._colors
        self._active_tab = tab
        self._clear_container()
        self._bind_activity()
        self._reset_auto_lock()

        self.bind("<Control-n>", lambda _e: self._open_new_credential())
        self.bind("<Control-f>", lambda _e: self._focus_credential_search())
        self.bind("<Control-l>", lambda _e: self._lock_vault())
        self.bind("<Control-s>", lambda _e: self._save_current_entry())

        shell = tk.Frame(self._container, bg=c["bg"])
        shell.pack(fill="both", expand=True)

        # Left Navigation Sidebar
        sidebar = tk.Frame(shell, bg=c["sidebar"], width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = tk.Frame(sidebar, bg=c["sidebar"], padx=16, pady=18)
        brand.pack(fill="x")
        tk.Label(brand, text="P.U.L.S.E.", bg=c["sidebar"], fg=c["accent"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(brand, text="S.H.I.E.L.D.", bg=c["sidebar"], fg=c["text"], font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(brand, text="V.A.U.L.T. Security Core", bg=c["sidebar"], fg=c["muted"], font=("Segoe UI", 8)).pack(
            anchor="w"
        )

        tk.Frame(sidebar, bg=c["border"], height=1).pack(fill="x", padx=14, pady=(0, 10))

        self._nav_buttons: dict[str, tk.Button] = {}
        nav_items = [
            ("dashboard", "  Security Dashboard"),
            ("credentials", "  Credential Library"),
            ("health", "  Health & Risk Audit"),
            ("identity", "  Identity & Devices"),
            ("governance", "  Governance & IR"),
            ("backup", "  Backup & Recovery"),
            ("audit", "  Security Audit Log"),
        ]
        for key, label in nav_items:
            btn = tk.Button(
                sidebar,
                text=label,
                command=lambda k=key: self._switch_tab(k),
                bg=c["sidebar"],
                fg=c["text"],
                activebackground=c["surface_alt"],
                activeforeground=c["text"],
                relief="flat",
                anchor="w",
                font=("Segoe UI", 10),
                padx=14,
                pady=10,
                cursor="hand2",
            )
            btn.pack(fill="x", padx=8, pady=2)
            self._nav_buttons[key] = btn

        # Sidebar Footer Utilities
        footer = tk.Frame(sidebar, bg=c["sidebar"], padx=12, pady=12)
        footer.pack(side="bottom", fill="x")
        tk.Frame(footer, bg=c["border"], height=1).pack(fill="x", pady=(0, 10))
        ttk.Button(footer, text="Password Generator", command=self._open_standalone_generator).pack(fill="x", pady=(0, 6))
        ttk.Button(
            footer,
            text="Switch to Light Theme" if self._theme_name == "dark" else "Switch to Dark Theme",
            command=self._toggle_theme,
        ).pack(fill="x", pady=(0, 6))
        ttk.Button(footer, text="Lock Vault (Ctrl+L)", style="Danger.TButton", command=self._lock_vault).pack(fill="x")

        # Main Content Area
        tk.Frame(shell, bg=c["border"], width=1).pack(side="left", fill="y")
        self._content_area = tk.Frame(shell, bg=c["bg"])
        self._content_area.pack(side="left", fill="both", expand=True)

        self._switch_tab(tab)

    def _switch_tab(self, tab: str) -> None:
        self._active_tab = tab
        c = self._colors
        for key, btn in self._nav_buttons.items():
            if key == tab:
                btn.configure(bg=c["accent"], fg="#ffffff", font=("Segoe UI", 10, "bold"))
            else:
                btn.configure(bg=c["sidebar"], fg=c["text"], font=("Segoe UI", 10))

        self._cancel_timers()
        for child in self._content_area.winfo_children():
            child.destroy()

        if tab == "dashboard":
            self._render_dashboard_view()
        elif tab == "credentials":
            self._render_credentials_view()
        elif tab == "health":
            self._render_health_view()
        elif tab == "identity":
            self._render_identity_view()
        elif tab == "governance":
            self._render_governance_view()
        elif tab == "backup":
            self._render_backup_view()
        elif tab == "audit":
            self._render_audit_view()

    # ------------------------------------------------------------------ #
    # VIEW 1: Executive Security Dashboard
    # ------------------------------------------------------------------ #

    def _render_dashboard_view(self) -> None:
        c = self._colors
        page = tk.Frame(self._content_area, bg=c["bg"], padx=22, pady=18)
        page.pack(fill="both", expand=True)

        entries = self._vault.list_entries()
        report = audit_vault(entries, hibp_counts=self._hibp_counts, web_scans=self._web_scans)
        chain_ok, chain_msg = self._vault.verify_audit_log_integrity()
        devices = self._vault.list_devices()
        trusted_count = sum(1 for d in devices if d.status == "trusted")

        # Header + Quick Actions
        hdr = tk.Frame(page, bg=c["bg"])
        hdr.pack(fill="x", pady=(0, 14))
        tk.Label(hdr, text="Security Dashboard", bg=c["bg"], fg=c["text"], font=("Segoe UI", 18, "bold")).pack(
            side="left"
        )
        ttk.Button(hdr, text="+ Add Credential", style="Accent.TButton", command=self._open_new_credential).pack(
            side="right"
        )
        ttk.Button(hdr, text="Health Audit", command=lambda: self._switch_tab("health")).pack(
            side="right", padx=(0, 8)
        )
        ttk.Button(hdr, text="Google Vault", command=self._open_google_dialog).pack(side="right", padx=(0, 8))

        # Top KPI Cards (matching spec dashboard!)
        cards = tk.Frame(page, bg=c["bg"])
        cards.pack(fill="x", pady=(0, 14))
        h_color = c["success"] if report.health_score >= 80 else c["warning"] if report.health_score >= 55 else c["danger"]
        kpis = [
            ("Vault Health", f"{report.health_score}/100", h_color, f"{report.risk_level} Risk"),
            ("Strong Passwords", str(report.strong_count), c["success"], f"of {report.total_entries} total"),
            ("Reused Passwords", str(report.reused_count), c["danger"] if report.reused_count else c["success"], "Reuse Protection Active"),
            ("Weak Passwords", str(report.weak_count), c["warning"] if report.weak_count else c["success"], "Entropy & Dictionary"),
            ("Potentially Exposed", str(report.potentially_exposed_count), c["danger"] if report.potentially_exposed_count else c["success"], "Breaches & Site Risks"),
        ]
        for idx, (title, val, color, sub) in enumerate(kpis):
            cards.columnconfigure(idx, weight=1)
            card = tk.Frame(cards, bg=c["surface"], padx=14, pady=14)
            card.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 8, 0))
            tk.Label(card, text=title, bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(anchor="w")
            tk.Label(card, text=val, bg=c["surface"], fg=color, font=("Segoe UI", 22, "bold")).pack(anchor="w", pady=(2, 2))
            tk.Label(card, text=sub, bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w")

        # 5 Pillars of Cybersecurity Live Compliance Strip
        pillars_frame = tk.Frame(page, bg=c["surface"], padx=14, pady=10)
        pillars_frame.pack(fill="x", pady=(0, 14))
        tk.Label(
            pillars_frame,
            text="5 PILLARS OF CYBERSECURITY (CIA + AUTHENTICITY + NON-REPUDIATION)",
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w", pady=(0, 6))
        pgrid = tk.Frame(pillars_frame, bg=c["surface"])
        pgrid.pack(fill="x")
        for idx, p in enumerate(self._vault.evaluate_five_pillars()):
            pgrid.columnconfigure(idx, weight=1)
            col = c["success"] if p["status"] == "STRONG" else c["warning"] if p["status"] == "ATTENTION" else c["danger"]
            cell = tk.Frame(pgrid, bg=c["input"], padx=8, pady=6)
            cell.grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 6, 0))
            tk.Label(cell, text=f"● {p['pillar']}", bg=c["input"], fg=c["text"], font=("Segoe UI", 8, "bold")).pack(
                anchor="w"
            )
            tk.Label(cell, text=p["status"], bg=c["input"], fg=col, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(
                cell, text=p["detail"], bg=c["input"], fg=c["muted"], font=("Segoe UI", 7), wraplength=175, justify="left"
            ).pack(anchor="w", pady=(2, 0))

        # Bottom Split: Priority Vulnerable Accounts | Recent Security Alerts
        split = tk.Frame(page, bg=c["bg"])
        split.pack(fill="both", expand=True)
        split.columnconfigure(0, weight=6)
        split.columnconfigure(1, weight=5)
        split.rowconfigure(0, weight=1)

        # Priority Vulnerable Accounts
        left = tk.Frame(split, bg=c["surface"], padx=14, pady=12)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        lh = tk.Frame(left, bg=c["surface"])
        lh.pack(fill="x", pady=(0, 8))
        tk.Label(lh, text="Priority Vulnerable Accounts", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            side="left"
        )
        ttk.Button(lh, text="View Full Audit", command=lambda: self._switch_tab("health")).pack(side="right")

        risky = [r for r in report.entry_results if r.risk_score > 0][:6]
        if not risky:
            tk.Label(
                left,
                text="All credentials look healthy! Add entries or run an opt-in HIBP breach check in Health & Risk Audit.",
                bg=c["surface"],
                fg=c["muted"],
                font=("Segoe UI", 9),
                wraplength=420,
                justify="left",
            ).pack(anchor="w", pady=12)
        else:
            for r in risky:
                row = tk.Frame(left, bg=c["input"], padx=10, pady=8)
                row.pack(fill="x", pady=3)
                rc = c["danger"] if r.risk_score >= 50 else c["warning"]
                tk.Label(row, text=f"{r.risk_score}/100", bg=c["input"], fg=rc, font=("Consolas", 10, "bold"), width=7).pack(
                    side="left"
                )
                info = tk.Frame(row, bg=c["input"])
                info.pack(side="left", fill="x", expand=True, padx=6)
                tk.Label(info, text=f"{r.title} ({r.category})", bg=c["input"], fg=c["text"], font=("Segoe UI", 9, "bold")).pack(
                    anchor="w"
                )
                top_issue = r.findings[0].title if r.findings else ""
                tk.Label(info, text=top_issue, bg=c["input"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w")
                ttk.Button(row, text="Fix", command=lambda eid=r.entry_id: self._jump_to_credential(eid)).pack(side="right")

        # Recent Security Alerts
        right = tk.Frame(split, bg=c["surface"], padx=14, pady=12)
        right.grid(row=0, column=1, sticky="nsew")
        rh = tk.Frame(right, bg=c["surface"])
        rh.pack(fill="x", pady=(0, 8))
        tk.Label(rh, text="Recent Security Events & Alerts", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            side="left"
        )
        ttk.Button(rh, text="Audit Log", command=lambda: self._switch_tab("audit")).pack(side="right")

        events = self._vault.list_audit_events(limit=8)
        for ev in events:
            erow = tk.Frame(right, bg=c["input"], padx=10, pady=6)
            erow.pack(fill="x", pady=2)
            sev_c = {
                "critical": c["danger"],
                "alert": c["danger"],
                "warning": c["warning"],
            }.get(ev.severity, c["accent"])
            tk.Label(erow, text=ev.severity.upper(), bg=c["input"], fg=sev_c, font=("Segoe UI", 7, "bold"), width=9).pack(
                side="left"
            )
            tk.Label(
                erow, text=ev.summary, bg=c["input"], fg=c["text"], font=("Segoe UI", 8), anchor="w"
            ).pack(side="left", fill="x", expand=True)

        tk.Label(
            right,
            text=(
                f"Hash Chain: {chain_msg} • App Integrity: "
                f"{'VERIFIED' if self._app_integrity.valid else 'ALERT'} ({self._app_integrity.checked_count} files)"
            ),
            bg=c["surface"],
            fg=c["muted"] if self._app_integrity.valid else c["danger"],
            font=("Segoe UI", 8),
        ).pack(side="bottom", anchor="w", pady=(8, 0))

    # ------------------------------------------------------------------ #
    # VIEW 2: Credential Library & Rich Detail Editor
    # ------------------------------------------------------------------ #

    def _open_new_credential(self) -> None:
        if self._active_tab != "credentials":
            self._switch_tab("credentials")
        self._start_new_entry()

    def _focus_credential_search(self) -> None:
        if self._active_tab != "credentials":
            self._switch_tab("credentials")
        if hasattr(self, "_search_entry") and self._search_entry.winfo_exists():
            self._search_entry.focus_set()

    def _jump_to_credential(self, entry_id: str) -> None:
        if self._active_tab != "credentials":
            self._switch_tab("credentials")
        entry = self._vault.get_entry(entry_id)
        if not entry:
            return
        self._search_var.set("")
        self._filter_cat_var.set("All")
        self._filter_type_var.set("All")
        self._filter_tag_var.set("All")
        self._fav_only_var.set(False)
        self._refresh_cred_list(select_id=entry_id)
        self._populate_editor(entry)

    def _render_credentials_view(self) -> None:
        c = self._colors
        page = tk.Frame(self._content_area, bg=c["bg"], padx=16, pady=12)
        page.pack(fill="both", expand=True)

        # Top Filter Bar
        fbar = tk.Frame(page, bg=c["surface"], padx=12, pady=8)
        fbar.pack(fill="x", pady=(0, 10))

        search_box = tk.Frame(fbar, bg=c["input"], padx=8, pady=2)
        search_box.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Label(search_box, text="Search:", bg=c["input"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refresh_cred_list())
        self._search_entry = tk.Entry(
            search_box,
            textvariable=self._search_var,
            bg=c["input"],
            fg=c["text"],
            insertbackground=c["text"],
            relief="flat",
            font=("Segoe UI", 10),
        )
        self._search_entry.pack(side="left", fill="x", expand=True, ipady=4)

        self._fav_only_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            fbar,
            text="★ Favorites",
            variable=self._fav_only_var,
            command=self._refresh_cred_list,
            bg=c["surface"],
            fg=c["warning"],
            selectcolor=c["input"],
            activebackground=c["surface"],
            activeforeground=c["warning"],
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left", padx=(0, 8))

        self._filter_type_var = tk.StringVar(value="All")
        type_cb = ttk.Combobox(fbar, textvariable=self._filter_type_var, values=("All",) + ENTRY_TYPES, state="readonly", width=13)
        type_cb.pack(side="left", padx=(0, 6))
        type_cb.bind("<<ComboboxSelected>>", lambda _e: self._refresh_cred_list())

        self._filter_cat_var = tk.StringVar(value="All")
        cat_cb = ttk.Combobox(fbar, textvariable=self._filter_cat_var, values=("All",) + CATEGORIES, state="readonly", width=11)
        cat_cb.pack(side="left", padx=(0, 6))
        cat_cb.bind("<<ComboboxSelected>>", lambda _e: self._refresh_cred_list())

        self._filter_tag_var = tk.StringVar(value="All")
        self._tag_cb = ttk.Combobox(fbar, textvariable=self._filter_tag_var, values=("All",), state="readonly", width=10)
        self._tag_cb.pack(side="left", padx=(0, 8))
        self._tag_cb.bind("<<ComboboxSelected>>", lambda _e: self._refresh_cred_list())

        ttk.Button(fbar, text="+ New Entry", style="Accent.TButton", command=self._start_new_entry).pack(side="right")

        # Split Panel
        body = tk.Frame(page, bg=c["bg"])
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=5)
        body.columnconfigure(1, weight=6)
        body.rowconfigure(0, weight=1)

        # Left Tree
        left = tk.Frame(body, bg=c["surface"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        lhdr = tk.Frame(left, bg=c["surface"], padx=10, pady=8)
        lhdr.grid(row=0, column=0, columnspan=2, sticky="ew")
        self._count_label = tk.Label(lhdr, text="Entries (0)", bg=c["surface"], fg=c["text"], font=("Segoe UI", 10, "bold"))
        self._count_label.pack(side="left")
        tk.Label(lhdr, text="Double-click to copy password", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(
            side="right"
        )

        self._tree = ttk.Treeview(
            left,
            columns=("fav", "title", "type", "username", "mfa"),
            show="headings",
            style="Vault.Treeview",
            selectmode="browse",
        )
        self._tree.heading("fav", text="★", anchor="center")
        self._tree.heading("title", text="Title", anchor="w")
        self._tree.heading("type", text="Type", anchor="w")
        self._tree.heading("username", text="Username / ID", anchor="w")
        self._tree.heading("mfa", text="2FA", anchor="center")
        self._tree.column("fav", width=28, minwidth=26, anchor="center", stretch=False)
        self._tree.column("title", width=145, minwidth=95)
        self._tree.column("type", width=90, minwidth=70, stretch=False)
        self._tree.column("username", width=130, minwidth=85)
        self._tree.column("mfa", width=44, minwidth=40, anchor="center", stretch=False)
        self._tree.grid(row=1, column=0, sticky="nsew")

        sc = ttk.Scrollbar(left, orient="vertical", command=self._tree.yview)
        sc.grid(row=1, column=1, sticky="ns")
        self._tree.configure(yscrollcommand=sc.set)
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self._tree.bind("<Double-1>", self._on_tree_double_click)

        # Right Editor Card
        self._right_panel = tk.Frame(body, bg=c["surface"], padx=16, pady=12)
        self._right_panel.grid(row=0, column=1, sticky="nsew")
        self._build_editor_panel()
        self._refresh_cred_list()
        self._show_empty_editor()
        self._schedule_totp_tick()

    def _build_editor_panel(self) -> None:
        c = self._colors
        self._empty_frame = tk.Frame(self._right_panel, bg=c["surface"])
        tk.Label(self._empty_frame, text="Select or Create a Credential", bg=c["surface"], fg=c["text"], font=("Segoe UI", 13, "bold")).pack(
            pady=(0, 6)
        )
        tk.Label(
            self._empty_frame,
            text="Store websites, apps, emails, API keys, Wi-Fi, software licences,\nrecovery codes, or secure notes — each with its own AES-256-GCM DEK.",
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
            justify="center",
        ).pack(pady=(0, 12))
        ttk.Button(self._empty_frame, text="+ Add Credential", style="Accent.TButton", command=self._start_new_entry).pack()

        self._form_frame = tk.Frame(self._right_panel, bg=c["surface"])

        top = tk.Frame(self._form_frame, bg=c["surface"])
        top.pack(fill="x", pady=(0, 6))
        self._editor_heading = tk.Label(top, text="Edit Credential", bg=c["surface"], fg=c["text"], font=("Segoe UI", 12, "bold"))
        self._editor_heading.pack(side="left")

        self._f_fav = tk.BooleanVar(value=False)
        tk.Checkbutton(
            top,
            text="★ Favorite",
            variable=self._f_fav,
            bg=c["surface"],
            fg=c["warning"],
            selectcolor=c["input"],
            activebackground=c["surface"],
            activeforeground=c["warning"],
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right")

        self._f_title = tk.StringVar()
        self._f_type = tk.StringVar(value="Website")
        self._f_category = tk.StringVar(value="General")
        self._f_tags = tk.StringVar()
        self._f_username = tk.StringVar()
        self._f_password = tk.StringVar()
        self._f_url = tk.StringVar()
        self._f_totp = tk.StringVar()
        self._f_passkey = tk.BooleanVar(value=False)

        # Title + Type + Category
        r1 = tk.Frame(self._form_frame, bg=c["surface"])
        r1.pack(fill="x", pady=(0, 6))
        r1.columnconfigure(0, weight=4)
        r1.columnconfigure(1, weight=2)
        r1.columnconfigure(2, weight=2)
        tk.Label(r1, text="Title *", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).grid(row=0, column=0, sticky="w")
        tk.Label(r1, text="Type", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).grid(row=0, column=1, sticky="w", padx=(6, 0))
        tk.Label(r1, text="Category", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).grid(row=0, column=2, sticky="w", padx=(6, 0))

        self._title_entry = tk.Entry(
            r1, textvariable=self._f_title, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 10)
        )
        self._title_entry.grid(row=1, column=0, sticky="ew", ipady=5)
        ttk.Combobox(r1, textvariable=self._f_type, values=ENTRY_TYPES, state="readonly", width=13).grid(
            row=1, column=1, sticky="ew", padx=(6, 0)
        )
        ttk.Combobox(r1, textvariable=self._f_category, values=CATEGORIES, state="readonly", width=11).grid(
            row=1, column=2, sticky="ew", padx=(6, 0)
        )

        # Username + Tags
        r2 = tk.Frame(self._form_frame, bg=c["surface"])
        r2.pack(fill="x", pady=(0, 6))
        r2.columnconfigure(0, weight=3)
        r2.columnconfigure(1, weight=2)
        tk.Label(r2, text="Username / Email / SSID / Key ID", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).grid(
            row=0, column=0, sticky="w"
        )
        tk.Label(r2, text="Tags (comma-separated)", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        u_wrap = tk.Frame(r2, bg=c["surface"])
        u_wrap.grid(row=1, column=0, sticky="ew")
        tk.Entry(
            u_wrap, textvariable=self._f_username, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 10)
        ).pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 4))
        ttk.Button(u_wrap, text="Copy", command=lambda: self._copy_to_clipboard(self._f_username.get(), "Username")).pack(
            side="right"
        )
        tk.Entry(
            r2, textvariable=self._f_tags, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 9)
        ).grid(row=1, column=1, sticky="ew", padx=(8, 0), ipady=5)

        # Password + Temporary Reveal (Adaptive) + Reuse Protection
        tk.Label(self._form_frame, text="Password / Secret / API Key", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(
            anchor="w"
        )
        prow = tk.Frame(self._form_frame, bg=c["surface"])
        prow.pack(fill="x", pady=(1, 3))
        self._pwd_entry = tk.Entry(
            prow, textvariable=self._f_password, show="•", bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Consolas", 10)
        )
        self._pwd_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 4))
        self._toggle_pwd_btn = ttk.Button(prow, text="Reveal", command=self._toggle_editor_password)
        self._toggle_pwd_btn.pack(side="left", padx=(0, 4))
        ttk.Button(
            prow,
            text="Copy",
            command=lambda: (
                self._copy_to_clipboard(self._f_password.get(), "Password", is_secret=True),
                self._vault.record_credential_event("password_copied", self._selected_entry_id or ""),
            ),
        ).pack(side="left", padx=(0, 4))
        ttk.Button(prow, text="Generate", command=self._open_entry_generator).pack(side="left")

        self._editor_strength = StrengthBar(self._form_frame, colors=c)
        self._editor_strength.pack(fill="x", pady=(0, 2))
        self._reuse_warning_label = tk.Label(
            self._form_frame, text="", bg=c["surface"], fg=c["danger"], font=("Segoe UI", 8, "bold"), anchor="w", wraplength=540, justify="left"
        )
        self._reuse_warning_label.pack(fill="x", pady=(0, 4))
        self._f_password.trace_add("write", lambda *_: self._on_editor_password_changed())

        # 2FA / TOTP + Passkey row
        totp_hdr = tk.Frame(self._form_frame, bg=c["surface"])
        totp_hdr.pack(fill="x")
        tk.Label(totp_hdr, text="2FA / TOTP Secret (Base32 or otpauth://)", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(
            side="left"
        )
        tk.Checkbutton(
            totp_hdr,
            text="Passkey Enabled",
            variable=self._f_passkey,
            bg=c["surface"],
            fg=c["accent"],
            selectcolor=c["input"],
            activebackground=c["surface"],
            activeforeground=c["accent"],
            font=("Segoe UI", 8, "bold"),
        ).pack(side="right")

        t_in = tk.Frame(self._form_frame, bg=c["surface"])
        t_in.pack(fill="x", pady=(1, 3))
        self._totp_entry = tk.Entry(
            t_in, textvariable=self._f_totp, show="•", bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Consolas", 9)
        )
        self._totp_entry.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 4))
        self._toggle_totp_btn = ttk.Button(t_in, text="Show", command=self._toggle_totp_secret)
        self._toggle_totp_btn.pack(side="left")

        live_row = tk.Frame(self._form_frame, bg=c["input"], padx=8, pady=4)
        live_row.pack(fill="x", pady=(0, 6))
        self._totp_code_label = tk.Label(live_row, text="No 2FA secret set", bg=c["input"], fg=c["muted"], font=("Consolas", 11, "bold"))
        self._totp_code_label.pack(side="left")
        self._totp_copy_btn = ttk.Button(live_row, text="Copy 2FA", command=self._copy_live_totp, state="disabled")
        self._totp_copy_btn.pack(side="right")
        self._totp_timer_label = tk.Label(live_row, text="", bg=c["input"], fg=c["muted"], font=("Segoe UI", 8))
        self._totp_timer_label.pack(side="right", padx=(0, 8))
        self._f_totp.trace_add("write", lambda *_: self._refresh_live_totp())

        # URL + inline vulnerability advisory
        tk.Label(self._form_frame, text="Website URL", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(anchor="w")
        urow = tk.Frame(self._form_frame, bg=c["surface"])
        urow.pack(fill="x", pady=(1, 2))
        tk.Entry(
            urow, textvariable=self._f_url, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 9)
        ).pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 4))
        ttk.Button(urow, text="Copy", command=lambda: self._copy_to_clipboard(self._f_url.get(), "URL")).pack(side="left", padx=(0, 4))
        ttk.Button(urow, text="Open", command=self._open_url).pack(side="left")

        self._url_advisory_label = tk.Label(
            self._form_frame, text="", bg=c["surface"], fg=c["warning"], font=("Segoe UI", 8), anchor="w", wraplength=540, justify="left"
        )
        self._url_advisory_label.pack(fill="x", pady=(0, 4))
        self._f_url.trace_add("write", lambda *_: self._check_url_advisory())

        # Custom Fields + Notes side by side
        bottom_fields = tk.Frame(self._form_frame, bg=c["surface"])
        bottom_fields.pack(fill="both", expand=True, pady=(0, 6))
        bottom_fields.columnconfigure(0, weight=1)
        bottom_fields.columnconfigure(1, weight=1)
        bottom_fields.rowconfigure(1, weight=1)

        tk.Label(bottom_fields, text="Custom Fields (Key: Value per line)", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).grid(
            row=0, column=0, sticky="w"
        )
        tk.Label(bottom_fields, text="Secure Notes / Recovery Codes", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        self._custom_fields_text = tk.Text(
            bottom_fields, height=4, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Consolas", 9), wrap="word", padx=6, pady=4
        )
        self._custom_fields_text.grid(row=1, column=0, sticky="nsew")
        self._notes_text = tk.Text(
            bottom_fields, height=4, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 9), wrap="word", padx=6, pady=4
        )
        self._notes_text.grid(row=1, column=1, sticky="nsew", padx=(8, 0))

        self._meta_label = tk.Label(self._form_frame, text="", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8), anchor="w")
        self._meta_label.pack(fill="x", pady=(0, 6))

        acts = tk.Frame(self._form_frame, bg=c["surface"])
        acts.pack(fill="x")
        self._delete_btn = ttk.Button(acts, text="Delete", style="Danger.TButton", command=self._delete_current_entry)
        self._delete_btn.pack(side="left")
        ttk.Button(acts, text="Save Entry (Ctrl+S)", style="Accent.TButton", command=self._save_current_entry).pack(side="right")
        ttk.Button(acts, text="Cancel", command=self._cancel_edit).pack(side="right", padx=(0, 6))

    def _on_editor_password_changed(self) -> None:
        pwd = self._f_password.get()
        self._editor_strength.update_password(pwd)
        if not self._vault.is_unlocked or not pwd:
            self._reuse_warning_label.configure(text="")
            return
        dupes = self._vault.find_password_reuse(pwd, exclude_entry_id=self._selected_entry_id)
        if dupes:
            names = ", ".join(e.title for e in dupes[:3])
            self._reuse_warning_label.configure(
                text=f"Reuse Protection Alert: Already used by {names}. Generate a unique password!"
            )
        else:
            self._reuse_warning_label.configure(text="")

    def _check_url_advisory(self) -> None:
        url = self._f_url.get().strip()
        if not url:
            self._url_advisory_label.configure(text="")
            return
        warns: list[str] = []
        if url.lower().startswith("http://"):
            warns.append("Insecure http:// URL — prefer https://.")
        m = match_known_site_advisory(url)
        if m:
            warns.append(f"Site Advisory ({m[0]}, {m[1]['year']}): {m[1]['advice']}")
        self._url_advisory_label.configure(text="  |  ".join(warns))

    def _refresh_live_totp(self) -> None:
        raw = self._f_totp.get().strip()
        if not raw:
            self._totp_code_label.configure(text="No 2FA secret set", fg=self._colors["muted"])
            self._totp_timer_label.configure(text="")
            self._totp_copy_btn.configure(state="disabled")
            return
        try:
            code, rem = get_totp_code(raw)
        except ValueError:
            self._totp_code_label.configure(text="Invalid TOTP secret", fg=self._colors["danger"])
            self._totp_timer_label.configure(text="")
            self._totp_copy_btn.configure(state="disabled")
            return
        self._totp_code_label.configure(
            text=f"{code[:3]} {code[3:]}", fg=self._colors["success"] if rem > 6 else self._colors["warning"]
        )
        self._totp_timer_label.configure(text=f"{rem}s")
        self._totp_copy_btn.configure(state="normal")

    def _schedule_totp_tick(self) -> None:
        if not self._vault.is_unlocked or self._active_tab != "credentials":
            return
        if hasattr(self, "_form_frame") and self._form_frame.winfo_exists() and self._form_frame.winfo_ismapped():
            self._refresh_live_totp()
        self._totp_tick_id = self.after(1000, self._schedule_totp_tick)

    def _copy_live_totp(self) -> None:
        raw = self._f_totp.get().strip()
        if not raw:
            return
        try:
            code, _ = get_totp_code(raw)
        except ValueError:
            return
        self._copy_to_clipboard(code, "2FA Code", is_secret=True)

    def _show_empty_editor(self) -> None:
        self._form_frame.pack_forget()
        self._empty_frame.place(relx=0.5, rely=0.45, anchor="center")

    def _show_form_editor(self) -> None:
        self._empty_frame.place_forget()
        self._form_frame.pack(fill="both", expand=True)

    def _set_editor_password_visible(self, visible: bool) -> None:
        if self._temp_reveal_timer_id is not None:
            self.after_cancel(self._temp_reveal_timer_id)
            self._temp_reveal_timer_id = None
        self._password_visible = visible
        self._pwd_entry.configure(show="" if visible else "•")
        self._toggle_pwd_btn.configure(text="Hide" if visible else "Reveal")
        if visible and self._vault.is_unlocked:
            secs = self._vault.adaptive_config.temp_reveal_seconds
            self._set_status(f"Password revealed temporarily (auto-hides in {secs}s).")
            self._temp_reveal_timer_id = self.after(
                secs * 1000,
                lambda: self._set_editor_password_visible(False)
                if hasattr(self, "_pwd_entry") and self._pwd_entry.winfo_exists()
                else None,
            )

    def _toggle_editor_password(self) -> None:
        if self._password_visible:
            self._set_editor_password_visible(False)
            return
        # Adaptive security check before revealing password!
        ok, _pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "reveal_password", self._colors, entry_category=self._f_category.get()
        )
        if not ok:
            return
        self._vault.record_credential_event("password_revealed", self._selected_entry_id or "")
        self._set_editor_password_visible(True)

    def _toggle_totp_secret(self) -> None:
        self._totp_secret_visible = not self._totp_secret_visible
        self._totp_entry.configure(show="" if self._totp_secret_visible else "•")
        self._toggle_totp_btn.configure(text="Hide" if self._totp_secret_visible else "Show")

    def _populate_editor(self, entry: VaultEntry) -> None:
        self._is_creating_new = False
        self._selected_entry_id = entry.id
        self._editor_heading.configure(text="Edit Credential")
        self._f_fav.set(entry.favorite)
        self._f_title.set(entry.title)
        self._f_type.set(entry.entry_type)
        self._f_category.set(entry.category)
        self._f_tags.set(", ".join(entry.tags))
        self._f_username.set(entry.username)
        self._f_password.set(entry.password)
        self._f_totp.set(entry.totp_secret)
        self._f_passkey.set(entry.passkey_enabled)
        self._f_url.set(entry.url)

        self._custom_fields_text.delete("1.0", "end")
        if entry.custom_fields:
            self._custom_fields_text.insert(
                "1.0", "\n".join(f"{k}: {v}" for k, v in entry.custom_fields.items())
            )
        self._notes_text.delete("1.0", "end")
        self._notes_text.insert("1.0", entry.notes)
        self._meta_label.configure(
            text=f"Per-Record AES-256-GCM DEK  •  Created: {entry.created_at}  •  Pwd Updated: {entry.password_updated_at}"
        )
        self._set_editor_password_visible(False)
        self._totp_secret_visible = False
        self._totp_entry.configure(show="•")
        self._toggle_totp_btn.configure(text="Show")
        self._delete_btn.pack(side="left")
        self._show_form_editor()
        self._on_editor_password_changed()
        self._refresh_live_totp()
        self._check_url_advisory()

    def _start_new_entry(self) -> None:
        if not self._vault.is_unlocked or self._active_tab != "credentials":
            return
        self._tree.selection_remove(self._tree.selection())
        self._is_creating_new = True
        self._selected_entry_id = None
        self._editor_heading.configure(text="New Credential")
        self._f_fav.set(False)
        self._f_title.set("")
        self._f_type.set("Website")
        self._f_category.set("General")
        self._f_tags.set("")
        self._f_username.set("")
        self._f_password.set("")
        self._f_totp.set("")
        self._f_passkey.set(False)
        self._f_url.set("")
        self._custom_fields_text.delete("1.0", "end")
        self._notes_text.delete("1.0", "end")
        self._meta_label.configure(text="Unsaved entry — will receive a unique 256-bit DEK on save")
        self._set_editor_password_visible(False)
        self._delete_btn.pack_forget()
        self._show_form_editor()
        self._refresh_live_totp()
        self._title_entry.focus_set()

    def _refresh_cred_list(self, select_id: str | None = None) -> None:
        if not self._vault.is_unlocked or self._active_tab != "credentials":
            return
        tags = self._vault.all_tags()
        self._tag_cb.configure(values=("All",) + tuple(tags))
        if self._filter_tag_var.get() not in ("All",) + tuple(tags):
            self._filter_tag_var.set("All")

        entries = self._vault.list_entries(
            query=self._search_var.get(),
            category=self._filter_cat_var.get(),
            entry_type=self._filter_type_var.get(),
            tag=self._filter_tag_var.get(),
            favorites_only=self._fav_only_var.get(),
        )
        for item in self._tree.get_children():
            self._tree.delete(item)
        for e in entries:
            fav = "★" if e.favorite else ""
            mfa = "2FA" if e.totp_secret else ("PK" if e.passkey_enabled else "—")
            self._tree.insert("", "end", iid=e.id, values=(fav, e.title, e.entry_type, e.username, mfa))

        total = self._vault.count()
        self._count_label.configure(
            text=f"Entries ({total})" if len(entries) == total else f"Showing {len(entries)} of {total}"
        )
        target_id = select_id or self._selected_entry_id
        if target_id and self._tree.exists(target_id):
            self._tree.selection_set(target_id)
            self._tree.see(target_id)

    def _on_tree_select(self, _event: tk.Event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        entry = self._vault.get_entry(sel[0])
        if entry:
            self._populate_editor(entry)

    def _on_tree_double_click(self, _event: tk.Event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        entry = self._vault.get_entry(sel[0])
        if entry:
            self._copy_to_clipboard(entry.password, f"Password for '{entry.title}'", is_secret=True)
            self._vault.record_credential_event("password_copied", entry.id)

    def _parse_custom_fields(self) -> dict[str, str]:
        raw = self._custom_fields_text.get("1.0", "end-1c")
        out: dict[str, str] = {}
        for line in raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip():
                    out[k.strip()] = v.strip()
        return out

    def _save_current_entry(self) -> None:
        if not self._vault.is_unlocked or self._active_tab != "credentials":
            return
        if not self._is_creating_new and self._selected_entry_id is None:
            return

        title = self._f_title.get().strip()
        if not title:
            messagebox.showwarning("Missing Title", "Please enter a title.")
            self._title_entry.focus_set()
            return

        pwd = self._f_password.get()
        totp_raw = self._f_totp.get().strip()
        if totp_raw:
            try:
                totp_raw = normalize_totp_secret(totp_raw)
            except ValueError as exc:
                messagebox.showwarning("Invalid TOTP Secret", str(exc))
                return

        # Security Policy Enforcement: minimum length & reuse policy (warn or block)
        pol = self._vault.security_policy
        if pwd and len(pwd) < pol.min_password_length:
            if not messagebox.askyesno(
                "Security Policy Warning (Minimum Length)",
                f"Active policy requires passwords of at least {pol.min_password_length} characters "
                f"(entered: {len(pwd)}).\n\nClick 'No' to strengthen it, or 'Yes' to save anyway.",
                icon="warning",
            ):
                return

        if pwd:
            dupes = self._vault.find_password_reuse(pwd, exclude_entry_id=self._selected_entry_id)
            if dupes:
                names = ", ".join(e.title for e in dupes[:4])
                if pol.reuse_policy == "block":
                    messagebox.showerror(
                        "Blocked by Reuse Policy",
                        f"Active Security Policy BLOCKS password reuse.\n\n"
                        f"This password is already used by: {names}.\n"
                        "Use the Password Generator to create a unique password.",
                    )
                    return
                if not messagebox.askyesno(
                    "Reuse Protection Warning",
                    f"This password is already used by: {names}.\n\nSave anyway (not recommended)?",
                    icon="warning",
                ):
                    return

        tags = [t.strip() for t in self._f_tags.get().split(",") if t.strip()]
        cf = self._parse_custom_fields()
        notes = self._notes_text.get("1.0", "end-1c")

        try:
            if self._is_creating_new:
                saved = self._vault.add_entry(
                    title=title,
                    entry_type=self._f_type.get(),
                    category=self._f_category.get(),
                    tags=tags,
                    favorite=self._f_fav.get(),
                    username=self._f_username.get(),
                    password=pwd,
                    url=self._f_url.get(),
                    totp_secret=totp_raw,
                    passkey_enabled=self._f_passkey.get(),
                    custom_fields=cf,
                    notes=notes,
                )
                self._set_status(f"Encrypted & saved '{saved.title}' with a fresh per-record DEK.")
            else:
                assert self._selected_entry_id is not None
                saved = self._vault.update_entry(
                    self._selected_entry_id,
                    title=title,
                    entry_type=self._f_type.get(),
                    category=self._f_category.get(),
                    tags=tags,
                    favorite=self._f_fav.get(),
                    username=self._f_username.get(),
                    password=pwd,
                    url=self._f_url.get(),
                    totp_secret=totp_raw,
                    passkey_enabled=self._f_passkey.get(),
                    custom_fields=cf,
                    notes=notes,
                )
                self._set_status(f"Updated '{saved.title}' (re-encrypted with fresh nonce).")
        except Exception as exc:
            messagebox.showerror("Save Error", str(exc))
            return

        self._populate_editor(saved)
        self._refresh_cred_list(select_id=saved.id)

    def _cancel_edit(self) -> None:
        if self._is_creating_new:
            self._is_creating_new = False
            self._show_empty_editor()
        elif self._selected_entry_id:
            e = self._vault.get_entry(self._selected_entry_id)
            if e:
                self._populate_editor(e)
            else:
                self._show_empty_editor()

    def _delete_current_entry(self) -> None:
        if not self._selected_entry_id:
            return
        entry = self._vault.get_entry(self._selected_entry_id)
        if not entry:
            return
        if not messagebox.askyesno("Delete Credential", f"Permanently delete '{entry.title}'?", icon="warning"):
            return
        self._vault.delete_entry(entry.id)
        self._selected_entry_id = None
        self._refresh_cred_list()
        self._show_empty_editor()
        self._set_status(f"Deleted '{entry.title}'.")

    def _open_url(self) -> None:
        raw = self._f_url.get().strip()
        if not raw:
            return
        url = raw if "://" in raw else f"https://{raw}"
        if not url.lower().startswith(("http://", "https://")):
            messagebox.showwarning("Unsupported URL", "Only http:// and https:// URLs are allowed.")
            return
        webbrowser.open(url)

    # ------------------------------------------------------------------ #
    # VIEW 3: Security Health, Website Vulnerability & Risk Audit
    # ------------------------------------------------------------------ #

    def _render_health_view(self) -> None:
        c = self._colors
        page = tk.Frame(self._content_area, bg=c["bg"], padx=20, pady=16)
        page.pack(fill="both", expand=True)

        hdr = tk.Frame(page, bg=c["bg"])
        hdr.pack(fill="x", pady=(0, 10))
        tk.Label(hdr, text="Security Health & Risk Intelligence", bg=c["bg"], fg=c["text"], font=("Segoe UI", 16, "bold")).pack(
            side="left"
        )
        self._hibp_btn = ttk.Button(hdr, text="Check Breaches (HIBP k-Anonymity)", style="Accent.TButton", command=self._run_hibp_check)
        self._hibp_btn.pack(side="right")
        self._web_btn = ttk.Button(hdr, text="Scan Websites (TLS & Headers)", command=self._run_web_scan)
        self._web_btn.pack(side="right", padx=(0, 6))
        ttk.Button(hdr, text="Export Report (.md)", command=self._export_health_report).pack(side="right", padx=(0, 6))

        self._health_scan_status = tk.Label(page, text="", bg=c["bg"], fg=c["muted"], font=("Segoe UI", 9))
        self._health_scan_status.pack(anchor="w", pady=(0, 8))

        # Summary Banner
        self._health_banner = tk.Frame(page, bg=c["surface"], padx=14, pady=12)
        self._health_banner.pack(fill="x", pady=(0, 10))

        # Priority Table
        tframe = tk.Frame(page, bg=c["surface"])
        tframe.pack(fill="both", expand=True, pady=(0, 10))
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)

        self._health_tree = ttk.Treeview(
            tframe,
            columns=("rank", "title", "risk", "level", "issues"),
            show="headings",
            style="Vault.Treeview",
            selectmode="browse",
        )
        for col, text, w, anc in (
            ("rank", "#", 38, "center"),
            ("title", "Account", 180, "w"),
            ("risk", "Risk Score", 85, "center"),
            ("level", "Priority", 90, "center"),
            ("issues", "Detected Risks", 460, "w"),
        ):
            self._health_tree.heading(col, text=text, anchor=anc)
            self._health_tree.column(col, width=w, anchor=anc, stretch=(col in ("title", "issues")))
        self._health_tree.grid(row=0, column=0, sticky="nsew")
        hsc = ttk.Scrollbar(tframe, orient="vertical", command=self._health_tree.yview)
        hsc.grid(row=0, column=1, sticky="ns")
        self._health_tree.configure(yscrollcommand=hsc.set)
        self._health_tree.bind("<<TreeviewSelect>>", self._on_health_select)
        self._health_tree.bind("<Double-1>", self._on_health_fix)

        # Reasoning & Recommendations Box
        dbox = tk.Frame(page, bg=c["surface"], padx=12, pady=10)
        dbox.pack(fill="x")
        dh = tk.Frame(dbox, bg=c["surface"])
        dh.pack(fill="x", pady=(0, 4))
        tk.Label(
            dh, text="Risk Explanation & Recommended Remediation (Double-click row to fix)", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9, "bold")
        ).pack(side="left")
        ttk.Button(dh, text="Fix Selected Account", command=self._on_health_fix).pack(side="right")

        self._health_detail = tk.Text(
            dbox, height=6, bg=c["input"], fg=c["text"], relief="flat", font=("Segoe UI", 9), wrap="word", padx=8, pady=6, state="disabled"
        )
        self._health_detail.pack(fill="x")

        self._populate_health_data()

    def _populate_health_data(self) -> None:
        if self._active_tab != "health":
            return
        c = self._colors
        report = audit_vault(
            self._vault.list_entries(), hibp_counts=self._hibp_counts, web_scans=self._web_scans
        )
        self._current_report: VaultAuditReport = report

        for child in self._health_banner.winfo_children():
            child.destroy()

        hc = c["success"] if report.health_score >= 80 else c["warning"] if report.health_score >= 55 else c["danger"]
        tk.Label(
            self._health_banner,
            text=f"Health: {report.health_score}/100  •  Risk: {report.risk_score}/100 ({report.risk_level})",
            bg=c["surface"],
            fg=hc,
            font=("Segoe UI", 13, "bold"),
        ).pack(side="left")
        tk.Label(
            self._health_banner,
            text=(
                f"Strong: {report.strong_count}  |  Reused: {report.reused_count}  |  Weak: {report.weak_count}  |  "
                f"Breached: {report.breached_count}  |  Site Risks: {report.vulnerable_site_count}  |  "
                f"No 2FA: {report.no_mfa_count}  |  Stale: {report.stale_count}"
            ),
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
        ).pack(side="right")

        for item in self._health_tree.get_children():
            self._health_tree.delete(item)
        for rank, res in enumerate(report.entry_results, 1):
            summary = " • ".join(f.title for f in res.findings[:3]) if res.findings else "All security checks passed"
            self._health_tree.insert(
                "", "end", iid=res.entry_id, values=(f"#{rank}", res.title, f"{res.risk_score}/100", res.risk_level, summary)
            )

    def _on_health_select(self, _e: tk.Event) -> None:
        sel = self._health_tree.selection()
        if not sel or not hasattr(self, "_current_report"):
            return
        res = next((r for r in self._current_report.entry_results if r.entry_id == sel[0]), None)
        if not res:
            return
        if not res.findings:
            txt = f"{res.title}: No risks identified (Risk Score 0/100)."
        else:
            lines = [f"{res.title} [{res.entry_type} / {res.category}] — Risk {res.risk_score}/100 ({res.risk_level})"]
            for f in res.findings:
                lines.append(f"  • [{f.severity.upper()}] {f.title} (+{f.penalty} risk): {f.detail}")
                lines.append(f"    -> Action: {f.recommendation}")
            txt = "\n".join(lines)
        self._health_detail.configure(state="normal")
        self._health_detail.delete("1.0", "end")
        self._health_detail.insert("1.0", txt)
        self._health_detail.configure(state="disabled")

    def _on_health_fix(self, _e: tk.Event | None = None) -> None:
        sel = self._health_tree.selection()
        if sel:
            self._jump_to_credential(sel[0])

    def _run_hibp_check(self) -> None:
        if self._health_scanning:
            return
        if not messagebox.askyesno(
            "Opt-In Breach Check (HIBP k-Anonymity)",
            "Check passwords against Have I Been Pwned?\n\n"
            "Only the first 5 characters of each password's SHA-1 hash are sent — plaintext passwords are NEVER transmitted.",
        ):
            return
        entries = self._vault.list_entries()
        self._health_scanning = True
        self._hibp_btn.configure(state="disabled")
        self._web_btn.configure(state="disabled")
        self._health_scan_status.configure(text="Running HIBP k-Anonymity breach check...")

        def worker() -> None:
            results: dict[str, int] = {}
            errs = 0
            for idx, e in enumerate(entries, 1):
                if not e.password:
                    continue
                try:
                    results[e.id] = check_hibp_pwned(e.password)
                except Exception:
                    errs += 1
                self.after(
                    0,
                    lambda i=idx, tot=len(entries): self._health_scan_status.configure(text=f"HIBP check: {i}/{tot}...")
                    if self._active_tab == "health" and self._health_scan_status.winfo_exists()
                    else None,
                )

            def finish() -> None:
                self._hibp_counts.update(results)
                self._health_scanning = False
                if self._active_tab == "health" and self._hibp_btn.winfo_exists():
                    self._hibp_btn.configure(state="normal")
                    self._web_btn.configure(state="normal")
                    note = f" ({errs} network errors)" if errs else ""
                    self._health_scan_status.configure(text=f"HIBP breach check complete{note}.")
                    self._populate_health_data()

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _run_web_scan(self) -> None:
        if self._health_scanning:
            return
        targets = [e for e in self._vault.list_entries() if e.url.strip()]
        if not targets:
            messagebox.showinfo("No Websites", "No entries have website URLs to scan.")
            return
        if not messagebox.askyesno(
            "Opt-In Website Vulnerability Scan",
            f"Inspect HTTPS/TLS certificates and HTTP security headers (HSTS, CSP, X-Frame-Options) for {len(targets)} saved URL(s)?\n\n"
            "No credentials are sent.",
        ):
            return
        self._health_scanning = True
        self._hibp_btn.configure(state="disabled")
        self._web_btn.configure(state="disabled")
        self._health_scan_status.configure(text="Scanning websites...")

        def worker() -> None:
            scans: dict[str, WebsiteScanResult] = {}
            for idx, e in enumerate(targets, 1):
                scans[e.id] = scan_website_security(e.url)
                self.after(
                    0,
                    lambda i=idx, tot=len(targets), t=e.title: self._health_scan_status.configure(
                        text=f"Scanning {t} ({i}/{tot})..."
                    )
                    if self._active_tab == "health" and self._health_scan_status.winfo_exists()
                    else None,
                )

            def finish() -> None:
                self._web_scans.update(scans)
                self._health_scanning = False
                if self._active_tab == "health" and self._web_btn.winfo_exists():
                    self._hibp_btn.configure(state="normal")
                    self._web_btn.configure(state="normal")
                    self._health_scan_status.configure(text=f"Website scan complete ({len(scans)} checked).")
                    self._populate_health_data()

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _export_health_report(self) -> None:
        if not hasattr(self, "_current_report"):
            return
        dest = filedialog.asksaveasfilename(
            title="Export Redacted Security Audit Report",
            defaultextension=".md",
            initialfile="SHIELD_Security_Audit.md",
            filetypes=[("Markdown Report", "*.md")],
        )
        if dest:
            Path(dest).write_text(self._current_report.to_markdown(), encoding="utf-8")
            self._set_status(f"Redacted audit report saved to {Path(dest).name}.")

    # ------------------------------------------------------------------ #
    # VIEW 4: Identity, MFA, Trusted Devices & Adaptive Security
    # ------------------------------------------------------------------ #

    def _render_identity_view(self) -> None:
        c = self._colors
        page = tk.Frame(self._content_area, bg=c["bg"], padx=22, pady=16)
        page.pack(fill="both", expand=True)

        tk.Label(page, text="Identity, MFA, Devices & Adaptive Security", bg=c["bg"], fg=c["text"], font=("Segoe UI", 16, "bold")).pack(
            anchor="w", pady=(0, 12)
        )

        # Row 1: MFA + Master Auth + Failed Login Monitor
        top = tk.Frame(page, bg=c["bg"])
        top.pack(fill="x", pady=(0, 12))
        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=1)

        mfa_card = tk.Frame(top, bg=c["surface"], padx=16, pady=14)
        mfa_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        tk.Label(mfa_card, text="Authentication & Vault MFA", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        mfa_st = (
            f"ACTIVE (Anti-Replay TOTP • {self._vault.remaining_mfa_recovery_codes} recovery codes left)"
            if self._vault.mfa_enabled
            else "DISABLED (Master password only)"
        )
        tk.Label(
            mfa_card, text=f"MFA Status: {mfa_st}", bg=c["surface"], fg=c["success"] if self._vault.mfa_enabled else c["warning"], font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", pady=(0, 4))
        tk.Label(
            mfa_card,
            text="No SMS/phone-number bypasses. Compatible with Microsoft/Google Auth, Aegis & 2FAS.",
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(0, 10))
        mbtns = tk.Frame(mfa_card, bg=c["surface"])
        mbtns.pack(fill="x")
        ttk.Button(mbtns, text="Configure Vault MFA", style="Accent.TButton", command=self._open_mfa_dialog).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(mbtns, text="Rotate Master Password", command=self._open_change_master_dialog).pack(side="left")

        stats_card = tk.Frame(top, bg=c["surface"], padx=16, pady=14)
        stats_card.grid(row=0, column=1, sticky="nsew")
        tk.Label(stats_card, text="Brute-Force & Rate-Limit Monitor", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        stats = self._vault.get_auth_stats()
        m_st = stats.get("master", {})
        f_st = stats.get("mfa", {})
        tk.Label(
            stats_card,
            text=(
                f"Master Password Failures (total): {m_st.get('total_failures', 0)}   •   "
                f"Last failure: {m_st.get('last_failure_at') or 'None'}\n"
                f"MFA Code Failures (total): {f_st.get('total_failures', 0)}   •   "
                f"Progressive lockout triggers after 3 consecutive failures."
            ),
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w")

        # Row 2: Trusted Devices Registry
        dev_card = tk.Frame(page, bg=c["surface"], padx=16, pady=12)
        dev_card.pack(fill="both", expand=True, pady=(0, 12))
        dh = tk.Frame(dev_card, bg=c["surface"])
        dh.pack(fill="x", pady=(0, 8))
        tk.Label(dh, text="Registered Trusted Devices", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            side="left"
        )
        ttk.Button(dh, text="Restore Trust", command=self._restore_selected_device).pack(side="right")
        ttk.Button(dh, text="Revoke Device", style="Danger.TButton", command=self._revoke_selected_device).pack(
            side="right", padx=(0, 6)
        )
        ttk.Button(dh, text="+ Register Device", command=self._add_external_device).pack(side="right", padx=(0, 6))

        self._dev_tree = ttk.Treeview(
            dev_card,
            columns=("id", "name", "os", "seen", "status"),
            show="headings",
            style="Vault.Treeview",
            height=5,
        )
        for col, text, w in (
            ("id", "Device ID", 130),
            ("name", "Device Name", 170),
            ("os", "Platform", 210),
            ("seen", "Last Seen", 160),
            ("status", "Status", 100),
        ):
            self._dev_tree.heading(col, text=text, anchor="w")
            self._dev_tree.column(col, width=w)
        self._dev_tree.pack(fill="both", expand=True)
        self._populate_devices()

        # Row 3: Adaptive Security Policy Controls
        pol_card = tk.Frame(page, bg=c["surface"], padx=16, pady=12)
        pol_card.pack(fill="x")
        tk.Label(pol_card, text="Adaptive Security Policy (Deterministic)", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        cfg = self._vault.adaptive_config
        self._ap_reveal = tk.BooleanVar(value=cfg.require_reauth_for_sensitive_reveal)
        self._ap_export = tk.BooleanVar(value=cfg.require_reauth_for_exports)
        self._ap_dev = tk.BooleanVar(value=cfg.require_reauth_for_device_management)
        self._ap_clip = tk.IntVar(value=cfg.clipboard_clear_seconds)
        self._ap_lock = tk.IntVar(value=cfg.auto_lock_seconds // 60)

        pgrid = tk.Frame(pol_card, bg=c["surface"])
        pgrid.pack(fill="x", pady=(0, 8))
        for idx, (lbl, var) in enumerate(
            (
                ("Require re-auth to reveal Finance/Email/Work passwords", self._ap_reveal),
                ("Require strong auth for all Vault Exports", self._ap_export),
                ("Require strong auth to Add/Revoke Devices", self._ap_dev),
            )
        ):
            tk.Checkbutton(
                pgrid,
                text=lbl,
                variable=var,
                bg=c["surface"],
                fg=c["text"],
                selectcolor=c["input"],
                activebackground=c["surface"],
                activeforeground=c["text"],
                font=("Segoe UI", 9),
            ).grid(row=idx, column=0, sticky="w", pady=1)

        trow = tk.Frame(pol_card, bg=c["surface"])
        trow.pack(fill="x")
        tk.Label(trow, text="Clipboard Clear (sec):", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        tk.Spinbox(trow, from_=5, to=120, width=5, textvariable=self._ap_clip, bg=c["input"], fg=c["text"], relief="flat").pack(
            side="left", padx=(0, 14)
        )
        tk.Label(trow, text="Auto-Lock Idle (min):", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        tk.Spinbox(trow, from_=1, to=60, width=5, textvariable=self._ap_lock, bg=c["input"], fg=c["text"], relief="flat").pack(
            side="left"
        )
        ttk.Button(trow, text="Save Policy", style="Accent.TButton", command=self._save_adaptive_policy).pack(side="right")

    def _populate_devices(self) -> None:
        for item in self._dev_tree.get_children():
            self._dev_tree.delete(item)
        for d in self._vault.list_devices():
            tag = f"{d.name} (This Device)" if d.is_current else d.name
            self._dev_tree.insert("", "end", iid=d.device_id, values=(d.device_id, tag, d.os_info, d.last_seen, d.status.upper()))

    def _add_external_device(self) -> None:
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "add_device", self._colors, force_master_password=True
        )
        if not ok:
            return
        name = simpledialog.askstring("Register Trusted Device", "Device name (e.g., Work Laptop):", parent=self)
        if not name:
            return
        os_info = simpledialog.askstring("Device Platform", "OS / Platform (e.g., Windows 11):", parent=self) or "External"
        self._vault.register_external_device(name, os_info, pwd)
        self._populate_devices()
        self._set_status(f"Registered trusted device '{name}'.")

    def _revoke_selected_device(self) -> None:
        sel = self._dev_tree.selection()
        if not sel:
            return
        dev_id = sel[0]
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "revoke_device", self._colors, force_master_password=True
        )
        if not ok:
            return
        self._vault.revoke_device(dev_id, pwd)
        self._populate_devices()
        self._set_status(f"Revoked device {dev_id}.")

    def _restore_selected_device(self) -> None:
        sel = self._dev_tree.selection()
        if not sel:
            return
        dev_id = sel[0]
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "manage_devices", self._colors, force_master_password=True
        )
        if not ok:
            return
        self._vault.trust_device(dev_id, pwd)
        self._populate_devices()
        self._set_status(f"Restored trust for {dev_id}.")

    def _save_adaptive_policy(self) -> None:
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "change_security_settings", self._colors, force_master_password=True
        )
        if not ok:
            return
        new_cfg = AdaptivePolicyConfig(
            require_reauth_for_sensitive_reveal=self._ap_reveal.get(),
            require_reauth_for_exports=self._ap_export.get(),
            require_reauth_for_security_changes=True,
            require_reauth_for_device_management=self._ap_dev.get(),
            temp_reveal_seconds=self._vault.adaptive_config.temp_reveal_seconds,
            clipboard_clear_seconds=max(5, int(self._ap_clip.get())),
            auto_lock_seconds=max(60, int(self._ap_lock.get()) * 60),
        )
        self._vault.update_adaptive_config(new_cfg, pwd)
        self._reset_auto_lock()
        self._set_status("Adaptive security policy updated.")

    # ------------------------------------------------------------------ #
    # VIEW 5: Governance, Risk, Incident Response, Patching & DR Workflows
    # ------------------------------------------------------------------ #

    def _render_governance_view(self) -> None:
        c = self._colors
        page = tk.Frame(self._content_area, bg=c["bg"], padx=20, pady=14)
        page.pack(fill="both", expand=True)

        hdr = tk.Frame(page, bg=c["bg"])
        hdr.pack(fill="x", pady=(0, 10))
        tk.Label(
            hdr,
            text="Governance, Risk, Incident Response, Patching & Recovery Workflows",
            bg=c["bg"],
            fg=c["text"],
            font=("Segoe UI", 15, "bold"),
        ).pack(side="left")
        ttk.Button(hdr, text="Export Governance Report (.md)", command=self._export_gov_report).pack(side="right")

        nb = ttk.Notebook(page)
        nb.pack(fill="both", expand=True)

        self._build_policies_subtab(nb)
        self._build_risk_subtab(nb)
        self._build_ir_subtab(nb)
        self._build_patching_subtab(nb)
        self._build_dr_workflows_subtab(nb)

    # --- Subtab 1: Security Policies ---
    def _build_policies_subtab(self, nb: ttk.Notebook) -> None:
        c = self._colors
        tab = tk.Frame(nb, bg=c["surface"], padx=16, pady=12)
        nb.add(tab, text="  Policies  ")

        score, checks = self._vault.evaluate_policy_compliance()
        sc_col = c["success"] if score >= 85 else c["warning"] if score >= 60 else c["danger"]
        tk.Label(
            tab,
            text=f"Policy Compliance: {score}%  ({sum(1 for x in checks if x.status == 'PASS')}/{len(checks)} controls passing)",
            bg=c["surface"],
            fg=sc_col,
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        tree = ttk.Treeview(
            tab, columns=("id", "name", "status", "viol", "detail"), show="headings", style="Vault.Treeview", height=8
        )
        for col, lbl, w in (
            ("id", "Policy ID", 95),
            ("name", "Security Policy Control", 230),
            ("status", "Status", 70),
            ("viol", "Violations", 75),
            ("detail", "Assessment Detail", 360),
        ):
            tree.heading(col, text=lbl, anchor="w")
            tree.column(col, width=w, stretch=(col == "detail"))
        for ch in checks:
            tree.insert("", "end", values=(ch.policy_id, ch.name, ch.status, str(ch.violations), ch.detail))
        tree.pack(fill="both", expand=True, pady=(0, 12))

        # Policy Configuration Editor
        pol = self._vault.security_policy
        cfg_box = tk.Frame(tab, bg=c["input"], padx=14, pady=10)
        cfg_box.pack(fill="x")
        tk.Label(
            cfg_box, text="Configure Enforced Security Policies (Requires Strong Re-Auth)", bg=c["input"], fg=c["text"], font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", pady=(0, 6))

        self._pol_min_len = tk.IntVar(value=pol.min_password_length)
        self._pol_max_age = tk.IntVar(value=pol.max_password_age_days)
        self._pol_reuse = tk.StringVar(value=pol.reuse_policy)
        self._pol_bak_days = tk.IntVar(value=pol.max_days_between_backups)
        self._pol_https = tk.BooleanVar(value=pol.require_https_urls)
        self._pol_hvmfa = tk.BooleanVar(value=pol.require_mfa_for_high_value)
        self._pol_vmfa = tk.BooleanVar(value=pol.require_vault_mfa)
        self._pol_rec = tk.BooleanVar(value=pol.require_recovery_kit)

        r1 = tk.Frame(cfg_box, bg=c["input"])
        r1.pack(fill="x", pady=(0, 6))
        tk.Label(r1, text="Min Length:", bg=c["input"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        tk.Spinbox(r1, from_=8, to=32, width=4, textvariable=self._pol_min_len, bg=c["surface"], fg=c["text"], relief="flat").pack(side="left", padx=(0, 12))
        tk.Label(r1, text="Max Age (days):", bg=c["input"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        tk.Spinbox(r1, from_=30, to=730, width=5, textvariable=self._pol_max_age, bg=c["surface"], fg=c["text"], relief="flat").pack(side="left", padx=(0, 12))
        tk.Label(r1, text="Reuse Mode:", bg=c["input"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        ttk.Combobox(r1, textvariable=self._pol_reuse, values=("warn", "block"), state="readonly", width=8).pack(side="left", padx=(0, 12))
        tk.Label(r1, text="Backup Cadence (d):", bg=c["input"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 4))
        tk.Spinbox(r1, from_=1, to=365, width=4, textvariable=self._pol_bak_days, bg=c["surface"], fg=c["text"], relief="flat").pack(side="left")

        r2 = tk.Frame(cfg_box, bg=c["input"])
        r2.pack(fill="x")
        for lbl, var in (
            ("Require HTTPS", self._pol_https),
            ("MFA on Finance/Email/Work", self._pol_hvmfa),
            ("Require Vault MFA", self._pol_vmfa),
            ("Require Recovery Kit", self._pol_rec),
        ):
            tk.Checkbutton(
                r2, text=lbl, variable=var, bg=c["input"], fg=c["text"], selectcolor=c["surface"],
                activebackground=c["input"], activeforeground=c["text"], font=("Segoe UI", 9)
            ).pack(side="left", padx=(0, 10))
        ttk.Button(r2, text="Save Policies", style="Accent.TButton", command=self._save_security_policies).pack(side="right")

    def _save_security_policies(self) -> None:
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "change_security_settings", self._colors, force_master_password=True
        )
        if not ok:
            return
        new_pol = SecurityPolicyConfig(
            min_password_length=int(self._pol_min_len.get()),
            max_password_age_days=int(self._pol_max_age.get()),
            reuse_policy=self._pol_reuse.get(),
            require_https_urls=self._pol_https.get(),
            require_mfa_for_high_value=self._pol_hvmfa.get(),
            require_vault_mfa=self._pol_vmfa.get(),
            require_recovery_kit=self._pol_rec.get(),
            max_days_between_backups=int(self._pol_bak_days.get()),
        )
        self._vault.update_security_policy(new_pol, pwd)
        self._set_status("Enforced security policies updated.")
        self._switch_tab("governance")

    # --- Subtab 2: Risk Register ---
    def _build_risk_subtab(self, nb: ttk.Notebook) -> None:
        c = self._colors
        tab = tk.Frame(nb, bg=c["surface"], padx=16, pady=12)
        nb.add(tab, text="  Risk Register  ")

        bar = tk.Frame(tab, bg=c["surface"])
        bar.pack(fill="x", pady=(0, 8))
        tk.Label(bar, text="Risk Management Register (Likelihood × Impact, 1–25)", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            side="left"
        )
        ttk.Button(bar, text="Close Risk", command=lambda: self._update_selected_risk_status("Closed")).pack(side="right")
        ttk.Button(bar, text="Accept Risk", command=lambda: self._update_selected_risk_status("Accepted")).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Mark Mitigating", command=lambda: self._update_selected_risk_status("Mitigating")).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="+ Add Risk", style="Accent.TButton", command=self._add_custom_risk).pack(side="right", padx=(0, 6))

        self._risk_tree = ttk.Treeview(
            tab, columns=("id", "score", "rating", "status", "cat", "title", "mit"), show="headings", style="Vault.Treeview"
        )
        for col, lbl, w in (
            ("id", "Risk ID", 105),
            ("score", "Score", 55),
            ("rating", "Rating", 75),
            ("status", "Status", 82),
            ("cat", "Category", 95),
            ("title", "Risk Description", 230),
            ("mit", "Mitigation Plan", 260),
        ):
            self._risk_tree.heading(col, text=lbl, anchor="w")
            self._risk_tree.column(col, width=w, stretch=(col in ("title", "mit")))
        self._risk_tree.pack(fill="both", expand=True)
        self._populate_risks()

    def _populate_risks(self) -> None:
        self._risk_map: dict[str, RiskRecord] = {}
        for item in self._risk_tree.get_children():
            self._risk_tree.delete(item)
        for r in self._vault.list_risk_register():
            self._risk_map[r.id] = r
            self._risk_tree.insert(
                "", "end", iid=r.id, values=(r.id, f"{r.score}/25", r.rating, r.status, r.category, r.title, r.mitigation)
            )

    def _add_custom_risk(self) -> None:
        title = simpledialog.askstring("New Risk Register Item", "Risk title / scenario:", parent=self)
        if not title or not title.strip():
            return
        like = simpledialog.askinteger("Likelihood (1-5)", "Likelihood (1=Rare, 5=Almost Certain):", minvalue=1, maxvalue=5, initialvalue=3, parent=self) or 3
        imp = simpledialog.askinteger("Impact (1-5)", "Impact (1=Minor, 5=Catastrophic):", minvalue=1, maxvalue=5, initialvalue=4, parent=self) or 4
        mit = simpledialog.askstring("Mitigation Plan", "Planned mitigation control:", parent=self) or ""
        rec = RiskRecord.from_dict(
            {"title": title.strip(), "category": "Operational", "likelihood": like, "impact": imp, "status": "Open", "mitigation": mit}
        )
        self._vault.upsert_risk(rec)
        self._populate_risks()
        self._set_status(f"Added risk {rec.id} ({rec.rating} {rec.score}/25).")

    def _update_selected_risk_status(self, new_status: str) -> None:
        sel = self._risk_tree.selection()
        if not sel:
            return
        rec = self._risk_map.get(sel[0])
        if not rec:
            return
        rec.status = new_status
        self._vault.upsert_risk(rec)
        self._populate_risks()
        self._set_status(f"Updated risk {rec.id} -> {new_status}.")

    # --- Subtab 3: Incident Response (IR) ---
    def _build_ir_subtab(self, nb: ttk.Notebook) -> None:
        c = self._colors
        tab = tk.Frame(nb, bg=c["surface"], padx=16, pady=12)
        nb.add(tab, text="  Incident Response  ")

        top = tk.Frame(tab, bg=c["surface"])
        top.pack(fill="x", pady=(0, 10))
        tk.Label(top, text="Playbook:", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(side="left", padx=(0, 6))
        self._ir_pb_var = tk.StringVar(value=next(iter(IR_PLAYBOOKS)))
        ttk.Combobox(top, textvariable=self._ir_pb_var, values=tuple(IR_PLAYBOOKS.keys()), state="readonly", width=36).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(top, text="+ Open Incident Case", style="Accent.TButton", command=self._open_ir_case).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(
            top, text="Emergency Containment / Lockdown", style="Danger.TButton", command=self._trigger_containment
        ).pack(side="right")

        split = tk.Frame(tab, bg=c["surface"])
        split.pack(fill="both", expand=True)
        split.columnconfigure(0, weight=4)
        split.columnconfigure(1, weight=6)
        split.rowconfigure(0, weight=1)

        self._ir_tree = ttk.Treeview(
            split, columns=("id", "sev", "phase", "title"), show="headings", style="Vault.Treeview"
        )
        for col, lbl, w in (("id", "Case", 82), ("sev", "Sev", 65), ("phase", "Phase", 75), ("title", "Incident", 170)):
            self._ir_tree.heading(col, text=lbl, anchor="w")
            self._ir_tree.column(col, width=w, stretch=(col == "title"))
        self._ir_tree.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self._ir_tree.bind("<<TreeviewSelect>>", self._on_select_ir_case)

        self._ir_detail = tk.Frame(split, bg=c["input"], padx=12, pady=10)
        self._ir_detail.grid(row=0, column=1, sticky="nsew")
        self._populate_ir_cases()

    def _populate_ir_cases(self, select_id: str | None = None) -> None:
        self._ir_map = {}
        for item in self._ir_tree.get_children():
            self._ir_tree.delete(item)
        for case in self._vault.list_incidents():
            self._ir_map[case.id] = case
            self._ir_tree.insert("", "end", iid=case.id, values=(case.id, case.severity.upper(), case.phase, case.title))
        if select_id and self._ir_tree.exists(select_id):
            self._ir_tree.selection_set(select_id)
            self._render_ir_detail(self._ir_map[select_id])
        elif self._ir_map:
            first = next(iter(self._ir_map.values()))
            self._ir_tree.selection_set(first.id)
            self._render_ir_detail(first)
        else:
            for ch in self._ir_detail.winfo_children():
                ch.destroy()
            tk.Label(
                self._ir_detail,
                text="No incident cases open.\nSelect a NIST IR playbook above to start a tracked response, or use Emergency Containment.",
                bg=self._colors["input"],
                fg=self._colors["muted"],
                font=("Segoe UI", 9),
                justify="left",
            ).pack(anchor="w", pady=10)

    def _open_ir_case(self) -> None:
        pb = self._ir_pb_var.get()
        case = self._vault.open_incident(pb)
        self._populate_ir_cases(select_id=case.id)
        self._set_status(f"Opened IR case {case.id} ({pb}).")

    def _on_select_ir_case(self, _e: tk.Event) -> None:
        sel = self._ir_tree.selection()
        if sel and sel[0] in self._ir_map:
            self._render_ir_detail(self._ir_map[sel[0]])

    def _render_ir_detail(self, case) -> None:
        c = self._colors
        for ch in self._ir_detail.winfo_children():
            ch.destroy()

        hdr = tk.Frame(self._ir_detail, bg=c["input"])
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text=f"{case.id} — {case.title}", bg=c["input"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            side="left"
        )
        phase_var = tk.StringVar(value=case.phase)
        p_cb = ttk.Combobox(hdr, textvariable=phase_var, values=IR_PHASES, state="readonly", width=11)
        p_cb.pack(side="right")

        def save_case_state() -> None:
            case.phase = phase_var.get()
            for idx, v in enumerate(step_vars):
                case.steps[idx]["done"] = v.get()
            self._vault.update_incident(case)
            self._populate_ir_cases(select_id=case.id)
            self._set_status(f"Saved IR case {case.id} (Phase: {case.phase}).")

        p_cb.bind("<<ComboboxSelected>>", lambda _e: save_case_state())

        tk.Label(
            self._ir_detail,
            text=f"Severity: {case.severity.upper()}  •  Opened: {case.opened_at}  •  Closed: {case.closed_at or 'Active'}",
            bg=c["input"],
            fg=c["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(0, 8))

        step_vars: list[tk.BooleanVar] = []
        for step in case.steps:
            v = tk.BooleanVar(value=bool(step.get("done", False)))
            step_vars.append(v)
            tk.Checkbutton(
                self._ir_detail,
                text=step.get("text", ""),
                variable=v,
                command=save_case_state,
                bg=c["input"],
                fg=c["text"],
                selectcolor=c["surface"],
                activebackground=c["input"],
                activeforeground=c["text"],
                font=("Segoe UI", 9),
                wraplength=470,
                justify="left",
            ).pack(anchor="w", pady=2)

    def _trigger_containment(self) -> None:
        if not messagebox.askyesno(
            "Emergency Containment / Lockdown",
            "Execute deterministic IR containment now?\n\n"
            "This will:\n"
            "  1. Preserve a forensic rolling SQLite snapshot\n"
            "  2. Revoke ALL other trusted devices\n"
            "  3. Record a CRITICAL Ed25519-signed containment event\n"
            "  4. Clear the clipboard and lock the vault",
            icon="warning",
        ):
            return
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "change_security_settings", self._colors, force_master_password=True
        )
        if not ok:
            return
        res = self._vault.execute_emergency_containment(pwd, revoke_other_devices=True)
        messagebox.showinfo(
            "Containment Executed",
            f"Forensic snapshot saved.\nRevoked other devices: {res['revoked_devices']}.\n\nLocking vault now.",
        )
        self._lock_vault("Emergency IR Containment executed — vault locked.")

    # --- Subtab 4: Patching & Dependency Security Posture ---
    def _build_patching_subtab(self, nb: ttk.Notebook) -> None:
        c = self._colors
        tab = tk.Frame(nb, bg=c["surface"], padx=16, pady=12)
        nb.add(tab, text="  Patching  ")

        bar = tk.Frame(tab, bg=c["surface"])
        bar.pack(fill="x", pady=(0, 8))
        tk.Label(
            bar, text="Runtime, Crypto Library & Security Dependency Patch Posture (Local / Zero-Telemetry)",
            bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")
        ).pack(side="left")
        update_cmd = "python -m pip install --user --upgrade -r requirements.txt"
        ttk.Button(
            bar, text="Copy Safe Update Command", command=lambda: self._copy_to_clipboard(update_cmd, "Update command")
        ).pack(side="right")

        tree = ttk.Treeview(
            tab, columns=("comp", "inst", "base", "stat", "rec"), show="headings", style="Vault.Treeview"
        )
        for col, lbl, w in (
            ("comp", "Component", 165),
            ("inst", "Installed", 165),
            ("base", "Secure Baseline", 125),
            ("stat", "Status", 85),
            ("rec", "Guidance", 320),
        ):
            tree.heading(col, text=lbl, anchor="w")
            tree.column(col, width=w, stretch=(col == "rec"))
        for p in self._vault.get_patch_posture():
            tree.insert("", "end", values=(p.component, p.installed_version, p.minimum_secure, p.status, p.recommendation))
        tree.pack(fill="both", expand=True)

    # --- Subtab 5: Recovery Workflows & Automated DR Readiness Drill ---
    def _build_dr_workflows_subtab(self, nb: ttk.Notebook) -> None:
        c = self._colors
        tab = tk.Frame(nb, bg=c["surface"], padx=16, pady=12)
        nb.add(tab, text="  Recovery Workflows & DR Drill  ")

        top = tk.Frame(tab, bg=c["surface"])
        top.pack(fill="x", pady=(0, 10))
        tk.Label(
            top, text="Automated Disaster Recovery Readiness Drill & Runbooks", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")
        ).pack(side="left")
        ttk.Button(top, text="Run Live DR Readiness Drill Now", style="Accent.TButton", command=self._run_dr_drill_ui).pack(
            side="right"
        )

        self._dr_output = tk.Text(
            tab, height=8, bg=c["input"], fg=c["text"], relief="flat", font=("Consolas", 9), wrap="word", padx=10, pady=8, state="disabled"
        )
        self._dr_output.pack(fill="x", pady=(0, 12))
        self._render_dr_drill_result(self._vault.last_dr_drill)

        wf_row = tk.Frame(tab, bg=c["surface"])
        wf_row.pack(fill="x", pady=(0, 6))
        tk.Label(wf_row, text="Guided Recovery Runbook:", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9, "bold")).pack(
            side="left", padx=(0, 8)
        )
        self._wf_var = tk.StringVar(value=next(iter(RECOVERY_WORKFLOWS)))
        wf_cb = ttk.Combobox(wf_row, textvariable=self._wf_var, values=tuple(RECOVERY_WORKFLOWS.keys()), state="readonly", width=40)
        wf_cb.pack(side="left")

        self._wf_text = tk.Text(
            tab, height=8, bg=c["input"], fg=c["text"], relief="flat", font=("Segoe UI", 9), wrap="word", padx=10, pady=8, state="disabled"
        )
        self._wf_text.pack(fill="both", expand=True)

        def show_wf(_e=None) -> None:
            steps = RECOVERY_WORKFLOWS.get(self._wf_var.get(), [])
            self._wf_text.configure(state="normal")
            self._wf_text.delete("1.0", "end")
            self._wf_text.insert("1.0", "\n\n".join(steps))
            self._wf_text.configure(state="disabled")

        wf_cb.bind("<<ComboboxSelected>>", show_wf)
        show_wf()

    def _render_dr_drill_result(self, res: dict | None) -> None:
        self._dr_output.configure(state="normal")
        self._dr_output.delete("1.0", "end")
        if not res:
            self._dr_output.insert(
                "1.0",
                "No Disaster Recovery Readiness Drill has been run yet.\n"
                "Click 'Run Live DR Readiness Drill Now' to test SQLite B-tree integrity, VMK record manifest, "
                "Ed25519 audit signatures, Recovery Kit readiness, and a live rolling snapshot restore check.",
            )
        else:
            lines = [f"DR DRILL STATUS: {res['overall_status']}   (Executed: {res['executed_at']})", "-" * 72]
            for ch in res.get("checks", []):
                lines.append(f"[{ch['status']:<4}] {ch['name']}: {ch['detail']}")
            self._dr_output.insert("1.0", "\n".join(lines))
        self._dr_output.configure(state="disabled")

    def _run_dr_drill_ui(self) -> None:
        res = self._vault.run_dr_readiness_drill()
        self._render_dr_drill_result(res)
        self._set_status(f"Disaster Recovery Readiness Drill completed: {res['overall_status']}.")

    def _export_gov_report(self) -> None:
        dest = filedialog.asksaveasfilename(
            title="Export Governance, Risk, IR & Patch Report",
            defaultextension=".md",
            initialfile="SHIELD_Governance_Risk_IR_Report.md",
            filetypes=[("Markdown Report", "*.md")],
        )
        if not dest:
            return
        out = self._vault.export_governance_report(dest)
        self._set_status(f"Redacted Governance report exported to {out.name}.")

    # ------------------------------------------------------------------ #
    # VIEW 6: Backup, Zero-Reset Recovery, Portability & E2EE
    # ------------------------------------------------------------------ #

    def _render_backup_view(self) -> None:
        c = self._colors
        page = tk.Frame(self._content_area, bg=c["bg"], padx=22, pady=16)
        page.pack(fill="both", expand=True)

        tk.Label(page, text="Backup, Recovery, Portability & E2EE", bg=c["bg"], fg=c["text"], font=("Segoe UI", 16, "bold")).pack(
            anchor="w", pady=(0, 12)
        )

        # Card 1: Zero-Reset Emergency Recovery Kit
        c1 = tk.Frame(page, bg=c["surface"], padx=16, pady=14)
        c1.pack(fill="x", pady=(0, 12))
        tk.Label(c1, text="1. Zero-Reset Emergency Recovery Kit", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        rk_status = "Configured (VMK wrapped under offline Recovery Key)" if self._vault.has_recovery_kit else "NOT CONFIGURED — Generate now to prevent permanent lockout!"
        tk.Label(
            c1,
            text=f"Status: {rk_status}",
            bg=c["surface"],
            fg=c["success"] if self._vault.has_recovery_kit else c["warning"],
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 8))
        ttk.Button(c1, text="Generate / Rotate Emergency Recovery Kit", style="Accent.TButton", command=self._generate_recovery_kit).pack(
            anchor="w"
        )

        # Card 2: Versioned Encrypted Backups & Restore Testing
        c2 = tk.Frame(page, bg=c["surface"], padx=16, pady=14)
        c2.pack(fill="x", pady=(0, 12))
        tk.Label(c2, text="2. Encrypted Backups & Integrity Verification (Default)", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        tk.Label(
            c2,
            text="Argon2id + AES-256-GCM encrypted backup files (.shield.enc). Test restore integrity anytime without overwriting your active vault.",
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(0, 10))
        b2 = tk.Frame(c2, bg=c["surface"])
        b2.pack(fill="x")
        ttk.Button(b2, text="Create Versioned Backup", style="Accent.TButton", command=self._create_versioned_backup).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(b2, text="Rolling DB Snapshot", command=self._create_snapshot_ui).pack(side="left", padx=(0, 6))
        ttk.Button(b2, text="Export Encrypted...", command=self._export_encrypted_backup).pack(side="left", padx=(0, 6))
        ttk.Button(b2, text="Verify Backup", command=self._verify_backup).pack(side="left", padx=(0, 6))
        ttk.Button(b2, text="Restore Backup...", command=self._restore_backup).pack(side="left", padx=(0, 6))
        ttk.Button(b2, text="Full Integrity Check", command=self._run_full_integrity_check).pack(side="left")

        # Card 3: E2EE Multi-Device Sync, X25519 Sharing & Google Vault
        c3 = tk.Frame(page, bg=c["surface"], padx=16, pady=14)
        c3.pack(fill="x", pady=(0, 12))
        tk.Label(c3, text="3. E2EE Sync, Secure Sharing & Google Vault", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 8)
        )
        b3 = tk.Frame(c3, bg=c["surface"])
        b3.pack(fill="x")
        ttk.Button(b3, text="E2EE Sync & X25519 Sharing...", style="Accent.TButton", command=self._open_e2ee_dialog).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(b3, text="Google Password Manager (Consent-Gated)...", command=self._open_google_dialog).pack(side="left")

        # Card 4: JSON Portability
        c4 = tk.Frame(page, bg=c["surface"], padx=16, pady=14)
        c4.pack(fill="x")
        tk.Label(c4, text="4. JSON Data Portability", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        tk.Label(
            c4,
            text="Encrypted backups are the default. Plaintext JSON export requires strong adaptive verification and must be treated as highly sensitive.",
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(0, 10))
        b4 = tk.Frame(c4, bg=c["surface"])
        b4.pack(fill="x")
        ttk.Button(b4, text="Import Plaintext JSON...", command=self._import_json).pack(side="left", padx=(0, 8))
        ttk.Button(b4, text="Export Plaintext JSON (Sensitive)...", style="Danger.TButton", command=self._export_plaintext_json).pack(
            side="left"
        )

    def _generate_recovery_kit(self) -> None:
        ok, _pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "generate_recovery_kit", self._colors, force_master_password=True
        )
        if not ok:
            return
        rec_key = self._vault.generate_emergency_recovery_kit()
        RecoveryKitDialog(
            self,
            rec_key,
            self._colors,
            on_copy_secret=lambda s, lbl: self._copy_to_clipboard(s, lbl, is_secret=True),
        )
        self._switch_tab("backup")

    def _create_versioned_backup(self) -> None:
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "export_vault", self._colors, force_master_password=True
        )
        if not ok:
            return
        backup_dir = self._vault.path.parent / "backups"
        out = self._vault.create_versioned_backup_in_dir(backup_dir, pwd)
        self._set_status(f"Versioned encrypted backup saved: {out.name}")
        messagebox.showinfo("Backup Created", f"Encrypted backup saved to:\n{out}")

    def _export_encrypted_backup(self) -> None:
        ok, pwd, _mfa = prompt_adaptive_reauth(
            self, self._vault, "export_vault", self._colors, force_master_password=True
        )
        if not ok:
            return
        dest = filedialog.asksaveasfilename(
            title="Export Encrypted S.H.I.E.L.D. Backup",
            defaultextension=".enc",
            initialfile="shield_backup.shield.enc",
            filetypes=[("S.H.I.E.L.D. Encrypted Backup", "*.enc")],
        )
        if not dest:
            return
        out = self._vault.export_encrypted_backup_file(dest, pwd)
        self._set_status(f"Encrypted backup exported: {out.name}")

    def _verify_backup(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Encrypted Backup to Verify",
            initialdir=str(self._vault.path.parent),
            filetypes=[("S.H.I.E.L.D. Encrypted Backup", "*.enc"), ("All Files", "*.*")],
        )
        if not path:
            return
        pwd = simpledialog.askstring("Backup Passphrase", "Enter the master password used to encrypt this backup:", show="•", parent=self)
        if not pwd:
            return
        res = self._vault.test_backup_restore_integrity(path, pwd)
        if res["valid"]:
            sig_txt = f"Verified ({res['signer_fingerprint']})" if res.get("signature_verified") else "Unsigned"
            messagebox.showinfo(
                "Backup Integrity & Authenticity Verified",
                f"{res['message']}\n\nCreated: {res['created_at']}\nKDF: {res['kdf']}\n"
                f"SHA-256: {res.get('sha256', '')[:32]}...\nEd25519 Signature: {sig_txt}\nVault ID: {res['vault_id']}",
            )
        else:
            messagebox.showerror("Verification Failed", res["message"])

    def _create_snapshot_ui(self) -> None:
        snap = self._vault.create_rolling_snapshot()
        count = len(self._vault.list_rolling_snapshots())
        self._set_status(f"Rolling SQLite snapshot created ({count} snapshots kept).")
        messagebox.showinfo("Snapshot Created", f"Online SQLite snapshot saved:\n{snap}\n\nTotal retained: {count} (max 5)")

    def _run_full_integrity_check(self) -> None:
        ok, msg = self._vault.verify_vault_integrity()
        if ok:
            messagebox.showinfo("Full Vault Integrity Verified", msg)
        else:
            messagebox.showerror("INTEGRITY ALERT", msg)

    def _restore_backup(self) -> None:
        path = filedialog.askopenfilename(
            title="Restore from Encrypted Backup",
            initialdir=str(self._vault.path.parent),
            filetypes=[("S.H.I.E.L.D. Encrypted Backup", "*.enc"), ("All Files", "*.*")],
        )
        if not path:
            return
        pwd = simpledialog.askstring("Backup Passphrase", "Enter the backup's master password:", show="•", parent=self)
        if not pwd:
            return
        try:
            stats = self._vault.restore_from_encrypted_backup(path, pwd, merge=True)
        except Exception as exc:
            messagebox.showerror("Restore Failed", str(exc))
            return
        msg = f"Restored backup: +{stats['added']} added, {stats['updated']} updated (Total: {stats['total']})."
        self._set_status(msg)
        messagebox.showinfo("Restore Complete", msg)

    def _import_json(self) -> None:
        path = filedialog.askopenfilename(title="Import JSON Credentials", filetypes=[("JSON Files", "*.json")])
        if not path:
            return
        try:
            imp, skip = self._vault.import_plaintext_json_file(path)
        except Exception as exc:
            messagebox.showerror("Import Error", str(exc))
            return
        self._set_status(f"Imported {imp} entries from JSON ({skip} duplicates skipped).")

    def _export_plaintext_json(self) -> None:
        ok, pwd, mfa = prompt_adaptive_reauth(
            self, self._vault, "export_plaintext_json", self._colors, force_master_password=True
        )
        if not ok:
            return
        if not messagebox.askyesno(
            "HIGHLY SENSITIVE — Plaintext JSON Export",
            "This file will contain ALL your passwords in UNENCRYPTED JSON.\n"
            "Encrypted backups (.shield.enc) are strongly preferred.\n\nProceed anyway?",
            icon="warning",
        ):
            return
        dest = filedialog.asksaveasfilename(
            title="Export Plaintext JSON", defaultextension=".json", initialfile="shield_export_SENSITIVE.json", filetypes=[("JSON", "*.json")]
        )
        if not dest:
            return
        out = self._vault.export_plaintext_json_file(dest, pwd, mfa_code=mfa)
        self._set_status(f"SENSITIVE plaintext JSON exported to {out.name}.")

    # ------------------------------------------------------------------ #
    # VIEW 6: Tamper-Evident Hash-Chained Audit Log
    # ------------------------------------------------------------------ #

    def _render_audit_view(self) -> None:
        c = self._colors
        page = tk.Frame(self._content_area, bg=c["bg"], padx=22, pady=16)
        page.pack(fill="both", expand=True)

        hdr = tk.Frame(page, bg=c["bg"])
        hdr.pack(fill="x", pady=(0, 10))
        tk.Label(hdr, text="Tamper-Evident Security Audit Log", bg=c["bg"], fg=c["text"], font=("Segoe UI", 16, "bold")).pack(
            side="left"
        )
        self._audit_sev_var = tk.StringVar(value="All")
        sev_cb = ttk.Combobox(
            hdr, textvariable=self._audit_sev_var, values=("All", "info", "warning", "alert", "critical"), state="readonly", width=11
        )
        sev_cb.pack(side="right", padx=(6, 0))
        sev_cb.bind("<<ComboboxSelected>>", lambda _e: self._populate_audit_log())
        ttk.Button(hdr, text="Export Signed Proof (.json)", command=self._export_signed_proof_ui).pack(
            side="right", padx=(6, 0)
        )
        ttk.Button(hdr, text="Verify Signatures & Chain", style="Accent.TButton", command=self._verify_chain_ui).pack(
            side="right"
        )

        self._chain_banner = tk.Label(page, text="", bg=c["surface"], fg=c["success"], font=("Segoe UI", 9, "bold"), anchor="w", padx=12, pady=8)
        self._chain_banner.pack(fill="x", pady=(0, 10))

        tframe = tk.Frame(page, bg=c["surface"])
        tframe.pack(fill="both", expand=True)
        tframe.rowconfigure(0, weight=1)
        tframe.columnconfigure(0, weight=1)

        self._audit_tree = ttk.Treeview(
            tframe,
            columns=("id", "ts", "sev", "event", "sig", "device", "summary"),
            show="headings",
            style="Vault.Treeview",
        )
        for col, text, w in (
            ("id", "#", 42),
            ("ts", "Timestamp (UTC)", 155),
            ("sev", "Severity", 72),
            ("event", "Event Type", 145),
            ("sig", "Non-Repudiation", 105),
            ("device", "Device", 110),
            ("summary", "Details (Secrets & Titles Redacted)", 310),
        ):
            self._audit_tree.heading(col, text=text, anchor="w")
            self._audit_tree.column(col, width=w, stretch=(col == "summary"))
        self._audit_tree.grid(row=0, column=0, sticky="nsew")
        asc = ttk.Scrollbar(tframe, orient="vertical", command=self._audit_tree.yview)
        asc.grid(row=0, column=1, sticky="ns")
        self._audit_tree.configure(yscrollcommand=asc.set)

        self._verify_chain_ui()
        self._populate_audit_log()

    def _verify_chain_ui(self) -> None:
        ok, msg = self._vault.verify_audit_log_integrity()
        c = self._colors
        self._chain_banner.configure(
            text=f"{'✔' if ok else '✖'} Ed25519 + SHA-256 Chain: {msg}  •  Signer: {self._vault.signing_fingerprint}",
            fg=c["success"] if ok else c["danger"],
        )

    def _export_signed_proof_ui(self) -> None:
        dest = filedialog.asksaveasfilename(
            title="Export Ed25519-Signed Audit Proof",
            defaultextension=".json",
            initialfile="SHIELD_Signed_Audit_Proof.json",
            filetypes=[("Signed JSON Proof", "*.json")],
        )
        if not dest:
            return
        out = self._vault.export_signed_audit_proof(dest)
        self._set_status(f"Signed non-repudiation audit proof saved to {out.name}.")
        self._populate_audit_log()

    def _populate_audit_log(self) -> None:
        for item in self._audit_tree.get_children():
            self._audit_tree.delete(item)
        events = self._vault.list_audit_events(limit=300, severity=self._audit_sev_var.get())
        for ev in events:
            sig_label = "Ed25519 ✔" if ev.is_signed else "PRE-AUTH"
            self._audit_tree.insert(
                "",
                "end",
                values=(f"#{ev.id}", ev.timestamp[:19], ev.severity.upper(), ev.event_type, sig_label, ev.device_id, ev.summary),
            )

    # ------------------------------------------------------------------ #
    # Shared Modal Launchers
    # ------------------------------------------------------------------ #

    def _open_standalone_generator(self) -> None:
        PasswordGeneratorDialog(
            self, self._colors, on_copy=lambda pwd: self._copy_to_clipboard(pwd, "Generated password", is_secret=True)
        )

    def _open_entry_generator(self) -> None:
        PasswordGeneratorDialog(
            self,
            self._colors,
            on_use=lambda pwd: (self._f_password.set(pwd), self._set_status("Generated password applied.")),
            on_copy=lambda pwd: self._copy_to_clipboard(pwd, "Generated password", is_secret=True),
        )

    def _open_mfa_dialog(self) -> None:
        ok, _pwd, _mfa = prompt_adaptive_reauth(self, self._vault, "change_mfa", self._colors)
        if not ok:
            return
        MFASetupDialog(
            self,
            self._vault,
            self._colors,
            on_changed=lambda msg: (self._set_status(msg), self._switch_tab(self._active_tab)),
            on_copy_secret=lambda s, lbl: self._copy_to_clipboard(s, lbl, is_secret=True),
        )

    def _open_e2ee_dialog(self) -> None:
        E2EESyncShareDialog(
            self,
            self._vault,
            self._colors,
            on_vault_changed=lambda msg: (self._set_status(msg), self._switch_tab(self._active_tab)),
        )

    def _open_google_dialog(self) -> None:
        GoogleVaultDialog(
            self,
            self._vault,
            self._colors,
            on_vault_changed=lambda msg: (self._set_status(msg), self._switch_tab(self._active_tab)),
            on_open_e2ee_sync=self._open_e2ee_dialog,
        )

    def _open_change_master_dialog(self) -> None:
        ChangeMasterPasswordDialog(
            self, self._vault, self._colors, on_changed=lambda: self._set_status("Master password rotated (VMK re-wrapped).")
        )


# Backwards-compatible alias
PasswordManagerApp = ShieldVaultApp


def main() -> None:
    _enable_windows_dpi_awareness()
    vault_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_VAULT_PATH
    app = ShieldVaultApp(vault_path=vault_path)
    app.mainloop()


if __name__ == "__main__":
    main()
