"""Themes, adaptive re-authentication, and modal dialogs for P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T."""

from __future__ import annotations

import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from shield_core.adaptive_security import SecurityRequirement
from shield_core.e2ee import E2EEError, SHARE_PW_PREFIX
from shield_core.google_sync import (
    GOOGLE_CHECKUP_URL,
    GOOGLE_PASSWORDS_URL,
    GOOGLE_SECURITY_URL,
    detect_google_drive_folders,
    export_google_passwords_csv,
    parse_google_passwords_csv,
    secure_delete_file,
)
from shield_core.mfa import build_otpauth_uri, build_qr_matrix, generate_totp_secret
from shield_core.password_gen import (
    SITE_POLICY_PRESETS,
    calculate_entropy,
    estimate_crack_time,
    evaluate_strength,
    generate_from_policy,
    generate_passphrase,
    generate_password,
)
from shield_core.vault_engine import InvalidMFACodeError, InvalidPasswordError, ShieldVault, VaultError

THEMES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#0b1120",
        "sidebar": "#0f172a",
        "surface": "#162033",
        "surface_alt": "#1e293b",
        "input": "#090f1d",
        "border": "#2d3c54",
        "text": "#f8fafc",
        "muted": "#94a3b8",
        "accent": "#3b82f6",
        "accent_hover": "#2563eb",
        "success": "#10b981",
        "warning": "#f59e0b",
        "danger": "#ef4444",
        "danger_hover": "#dc2626",
        "select": "#1d4ed8",
    },
    "light": {
        "bg": "#f1f5f9",
        "sidebar": "#e2e8f0",
        "surface": "#ffffff",
        "surface_alt": "#e2e8f0",
        "input": "#f8fafc",
        "border": "#cbd5e1",
        "text": "#0f172a",
        "muted": "#475569",
        "accent": "#2563eb",
        "accent_hover": "#1d4ed8",
        "success": "#059669",
        "warning": "#d97706",
        "danger": "#dc2626",
        "danger_hover": "#b91c1c",
        "select": "#2563eb",
    },
}


def center_window(win: tk.Toplevel, parent: tk.Misc) -> None:
    win.update_idletasks()
    px = parent.winfo_rootx() + (parent.winfo_width() - win.winfo_width()) // 2
    py = parent.winfo_rooty() + (parent.winfo_height() - win.winfo_height()) // 2
    win.geometry(f"+{max(30, px)}+{max(30, py)}")


class StrengthBar(tk.Frame):
    """4-segment password strength indicator with entropy bits and offline crack-time estimate."""

    def __init__(self, master: tk.Misc, colors: dict[str, str], show_entropy: bool = True) -> None:
        super().__init__(master, bg=colors["surface"])
        self._colors = colors
        self._show_entropy = show_entropy
        self._bars: list[tk.Frame] = []
        bar_row = tk.Frame(self, bg=colors["surface"])
        bar_row.pack(side="left", fill="x", expand=True)
        for _ in range(4):
            seg = tk.Frame(bar_row, height=6, bg=colors["border"])
            seg.pack(side="left", fill="x", expand=True, padx=(0, 4))
            self._bars.append(seg)
        self._label = tk.Label(
            self, text="", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 8), anchor="e"
        )
        self._label.pack(side="right", padx=(6, 0))

    def update_password(self, password: str) -> None:
        score, label, color = evaluate_strength(password)
        for idx, bar in enumerate(self._bars):
            bar.configure(bg=color if idx < score else self._colors["border"])
        if not password:
            self._label.configure(text="", fg=self._colors["muted"])
            return
        if self._show_entropy:
            bits = calculate_entropy(password)
            crack = estimate_crack_time(bits)
            self._label.configure(text=f"{label} • {bits:.0f}b ({crack})", fg=color)
        else:
            self._label.configure(text=label, fg=color)


# ====================================================================== #
# 1. Adaptive Security Re-Authentication Dialog
# ====================================================================== #


class ReAuthDialog(tk.Toplevel):
    """Deterministic adaptive re-authentication prompt for sensitive operations."""

    def __init__(
        self,
        parent: tk.Misc,
        vault: ShieldVault,
        requirement: SecurityRequirement,
        colors: dict[str, str],
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — Adaptive Security Verification")
        self.configure(bg=colors["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._req = requirement
        self.verified = False
        self.master_password = ""
        self.mfa_code = ""

        card = tk.Frame(self, bg=colors["surface"], padx=22, pady=18)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        badge_color = colors["danger"] if requirement.level == "strong" else colors["warning"]
        tk.Label(
            card,
            text=f"ADAPTIVE SECURITY ({requirement.level.upper()} VERIFICATION)",
            bg=colors["surface"],
            fg=badge_color,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            card,
            text="Confirm Your Identity",
            bg=colors["surface"],
            fg=colors["text"],
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(2, 6))
        tk.Label(
            card,
            text=requirement.reason,
            bg=colors["surface"],
            fg=colors["muted"],
            font=("Segoe UI", 9),
            wraplength=360,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        self._pwd_var = tk.StringVar()
        self._mfa_var = tk.StringVar()

        tk.Label(card, text="Master Password", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 3)
        )
        pwd_entry = tk.Entry(
            card,
            textvariable=self._pwd_var,
            show="•",
            bg=colors["input"],
            fg=colors["text"],
            insertbackground=colors["text"],
            relief="flat",
            font=("Segoe UI", 11),
            width=34,
        )
        pwd_entry.pack(fill="x", ipady=6, pady=(0, 10))
        pwd_entry.focus_set()

        if requirement.require_mfa:
            tk.Label(
                card,
                text="6-Digit MFA Authenticator Code",
                bg=colors["surface"],
                fg=colors["muted"],
                font=("Segoe UI", 9),
            ).pack(anchor="w", pady=(0, 3))
            tk.Entry(
                card,
                textvariable=self._mfa_var,
                bg=colors["input"],
                fg=colors["text"],
                insertbackground=colors["text"],
                relief="flat",
                font=("Consolas", 12),
                justify="center",
            ).pack(fill="x", ipady=6, pady=(0, 10))

        self._err = tk.Label(card, text="", bg=colors["surface"], fg=colors["danger"], font=("Segoe UI", 9))
        self._err.pack(anchor="w", pady=(0, 10))

        btns = tk.Frame(card, bg=colors["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")
        ttk.Button(btns, text="Verify & Continue", style="Accent.TButton", command=self._submit).pack(side="right")

        self.bind("<Return>", lambda _e: self._submit())
        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)

    def _submit(self) -> None:
        pwd = self._pwd_var.get()
        mfa = self._mfa_var.get().strip()
        if not pwd:
            self._err.configure(text="Master password is required.")
            return
        if self._req.require_mfa and not mfa:
            self._err.configure(text="6-digit MFA code is required for this high-sensitivity action.")
            return
        try:
            self._vault.verify_reauth(pwd, mfa_code=mfa, require_mfa=self._req.require_mfa)
        except Exception as exc:
            self._err.configure(text=str(exc))
            return

        self.verified = True
        self.master_password = pwd
        self.mfa_code = mfa
        self.destroy()


def prompt_adaptive_reauth(
    parent: tk.Misc,
    vault: ShieldVault,
    action: str,
    colors: dict[str, str],
    *,
    entry_category: str = "General",
    force_master_password: bool = False,
) -> tuple[bool, str, str]:
    """Evaluate adaptive security policy and prompt if required. Returns (ok, master_password, mfa_code)."""
    req = vault.evaluate_security_action(action, entry_category=entry_category)
    if not req.require_master_password and not force_master_password:
        return True, "", ""
    if force_master_password and not req.require_master_password:
        req = SecurityRequirement(
            action, "strong", True, vault.mfa_enabled, "Confirm your master password to authorize this cryptographic operation."
        )
    dlg = ReAuthDialog(parent, vault, req, colors)
    parent.wait_window(dlg)
    return dlg.verified, dlg.master_password, dlg.mfa_code


# ====================================================================== #
# 2. Zero-Reset Emergency Recovery Kit Display & Vault Recovery Dialogs
# ====================================================================== #


class RecoveryKitDialog(tk.Toplevel):
    """Displays a newly generated 200-bit Emergency Recovery Key (shown once)."""

    def __init__(
        self,
        parent: tk.Misc,
        recovery_key: str,
        colors: dict[str, str],
        on_copy_secret: Callable[[str, str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — Emergency Recovery Kit")
        self.configure(bg=colors["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self._on_copy_secret = on_copy_secret

        card = tk.Frame(self, bg=colors["surface"], padx=24, pady=20)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        tk.Label(
            card,
            text="ZERO-RESET EMERGENCY RECOVERY KIT",
            bg=colors["surface"],
            fg=colors["warning"],
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            card,
            text="Save This Recovery Key Offline Now",
            bg=colors["surface"],
            fg=colors["text"],
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", pady=(2, 8))
        tk.Label(
            card,
            text=(
                "P.U.L.S.E. S.H.I.E.L.D. enforces a zero-reset architecture: there is NO master-password reset.\n"
                "If you forget your master password, this Emergency Recovery Key is the ONLY way to unwrap "
                "your encrypted vault. Print it or store it securely offline — it will NOT be shown again."
            ),
            bg=colors["surface"],
            fg=colors["muted"],
            font=("Segoe UI", 9),
            wraplength=470,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))

        key_box = tk.Entry(
            card,
            bg=colors["input"],
            fg=colors["success"],
            readonlybackground=colors["input"],
            relief="flat",
            font=("Consolas", 11, "bold"),
            justify="center",
            width=54,
        )
        key_box.insert(0, recovery_key)
        key_box.configure(state="readonly")
        key_box.pack(fill="x", ipady=10, pady=(0, 14))

        def save_kit() -> None:
            dest = filedialog.asksaveasfilename(
                title="Save Emergency Recovery Kit",
                defaultextension=".txt",
                initialfile="SHIELD_Emergency_Recovery_Kit.txt",
                filetypes=[("Text File", "*.txt")],
                parent=self,
            )
            if dest:
                Path(dest).write_text(
                    "P.U.L.S.E. S.H.I.E.L.D. / V.A.U.L.T. — EMERGENCY RECOVERY KIT\n"
                    "Keep this offline in a physical safe. Anyone with this key + your vault DB can recover access.\n\n"
                    f"Recovery Key:\n{recovery_key}\n",
                    encoding="utf-8",
                )

        def copy_rec_key() -> None:
            if self._on_copy_secret:
                self._on_copy_secret(recovery_key, "Emergency Recovery Key")
            else:
                self.clipboard_clear()
                self.clipboard_append(recovery_key)

        btns = tk.Frame(card, bg=colors["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Copy Key (Auto-Clears)", command=copy_rec_key).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Save Kit (.txt)", command=save_kit).pack(side="left")
        ttk.Button(btns, text="I Have Saved It Safely", style="Accent.TButton", command=self.destroy).pack(
            side="right"
        )

        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)


class VaultRecoveryDialog(tk.Toplevel):
    """Recover a locked vault using its pre-generated Emergency Recovery Key."""

    def __init__(
        self,
        parent: tk.Misc,
        vault: ShieldVault,
        colors: dict[str, str],
        on_recovered: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — Emergency Vault Recovery")
        self.configure(bg=colors["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._on_recovered = on_recovered

        card = tk.Frame(self, bg=colors["surface"], padx=22, pady=18)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        tk.Label(
            card, text="Recover Vault via Emergency Recovery Key", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", pady=(0, 6))
        tk.Label(
            card,
            text="Enter your SHIELD-XXXXX-... Emergency Recovery Key and choose a new Master Password (min 8 chars).",
            bg=colors["surface"],
            fg=colors["muted"],
            font=("Segoe UI", 9),
            wraplength=420,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        self._rec_var = tk.StringVar()
        self._new_var = tk.StringVar()
        self._conf_var = tk.StringVar()

        tk.Label(card, text="Emergency Recovery Key", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 3)
        )
        tk.Entry(
            card,
            textvariable=self._rec_var,
            bg=colors["input"],
            fg=colors["text"],
            insertbackground=colors["text"],
            relief="flat",
            font=("Consolas", 10),
            width=48,
        ).pack(fill="x", ipady=6, pady=(0, 10))

        tk.Label(card, text="New Master Password (min 8 chars)", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 3)
        )
        tk.Entry(
            card,
            textvariable=self._new_var,
            show="•",
            bg=colors["input"],
            fg=colors["text"],
            insertbackground=colors["text"],
            relief="flat",
            font=("Segoe UI", 11),
        ).pack(fill="x", ipady=6, pady=(0, 6))

        bar = StrengthBar(card, colors=colors)
        bar.pack(fill="x", pady=(0, 10))
        self._new_var.trace_add("write", lambda *_: bar.update_password(self._new_var.get()))

        tk.Label(card, text="Confirm New Master Password", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 3)
        )
        tk.Entry(
            card,
            textvariable=self._conf_var,
            show="•",
            bg=colors["input"],
            fg=colors["text"],
            insertbackground=colors["text"],
            relief="flat",
            font=("Segoe UI", 11),
        ).pack(fill="x", ipady=6, pady=(0, 8))

        self._err = tk.Label(card, text="", bg=colors["surface"], fg=colors["danger"], font=("Segoe UI", 9), wraplength=420)
        self._err.pack(anchor="w", pady=(0, 10))

        btns = tk.Frame(card, bg=colors["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")
        ttk.Button(btns, text="Recover & Reset Master Key", style="Accent.TButton", command=self._submit).pack(
            side="right"
        )

        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)

    def _submit(self) -> None:
        rk = self._rec_var.get().strip()
        np = self._new_var.get()
        cp = self._conf_var.get()
        if not rk:
            self._err.configure(text="Enter your Emergency Recovery Key.")
            return
        if len(np) < 8:
            self._err.configure(text="New master password must be at least 8 characters.")
            return
        if np != cp:
            self._err.configure(text="Passwords do not match.")
            return
        try:
            self._vault.recover_vault_with_recovery_key(rk, np)
        except Exception as exc:
            self._err.configure(text=str(exc))
            return
        self.destroy()
        self._on_recovered()


# ====================================================================== #
# 3. Advanced Password, Passphrase & Site-Policy Generator Dialog
# ====================================================================== #


class PasswordGeneratorDialog(tk.Toplevel):
    """Generator supporting random chars, extended/custom chars, passphrases, and site-specific policies."""

    def __init__(
        self,
        parent: tk.Misc,
        colors: dict[str, str],
        on_use: Callable[[str], None] | None = None,
        on_copy: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — Password & Passphrase Generator")
        self.configure(bg=colors["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._colors = colors
        self._on_use = on_use
        self._on_copy = on_copy
        self._preview_var = tk.StringVar()

        self._policy_var = tk.StringVar(value="Custom")
        self._length_var = tk.IntVar(value=20)
        self._upper_var = tk.BooleanVar(value=True)
        self._lower_var = tk.BooleanVar(value=True)
        self._digits_var = tk.BooleanVar(value=True)
        self._symbols_var = tk.BooleanVar(value=True)
        self._extended_var = tk.BooleanVar(value=False)
        self._ambiguous_var = tk.BooleanVar(value=False)
        self._custom_var = tk.StringVar(value="")
        self._min_digits_var = tk.IntVar(value=2)
        self._min_symbols_var = tk.IntVar(value=2)

        self._words_var = tk.IntVar(value=5)
        self._sep_var = tk.StringVar(value="-")
        self._cap_var = tk.BooleanVar(value=True)
        self._phrase_num_var = tk.BooleanVar(value=True)
        self._phrase_sym_var = tk.BooleanVar(value=True)

        card = tk.Frame(self, bg=colors["surface"], padx=20, pady=18)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        tk.Label(
            card,
            text="Cryptographic Password Generator (Python secrets)",
            bg=colors["surface"],
            fg=colors["text"],
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        preview = tk.Entry(
            card,
            textvariable=self._preview_var,
            bg=colors["input"],
            fg=colors["text"],
            readonlybackground=colors["input"],
            relief="flat",
            font=("Consolas", 12),
            state="readonly",
            width=46,
        )
        preview.pack(fill="x", ipady=9, pady=(0, 8))

        self._strength = StrengthBar(card, colors=colors, show_entropy=True)
        self._strength.pack(fill="x", pady=(0, 12))

        self._tabs = ttk.Notebook(card)
        self._tabs.pack(fill="both", expand=True, pady=(0, 14))
        self._tabs.bind("<<NotebookTabChanged>>", lambda _e: self._regenerate())

        # Tab 1: Random Password + Site-Specific Policy
        rand_tab = tk.Frame(self._tabs, bg=colors["surface"], padx=10, pady=10)
        self._tabs.add(rand_tab, text="  Random & Site Policy  ")

        pol_row = tk.Frame(rand_tab, bg=colors["surface"])
        pol_row.pack(fill="x", pady=(0, 10))
        tk.Label(pol_row, text="Site Policy Preset:", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            side="left", padx=(0, 8)
        )
        pol_combo = ttk.Combobox(
            pol_row,
            textvariable=self._policy_var,
            values=("Custom",) + tuple(SITE_POLICY_PRESETS.keys()),
            state="readonly",
            width=36,
        )
        pol_combo.pack(side="left", fill="x", expand=True)
        pol_combo.bind("<<ComboboxSelected>>", lambda _e: self._apply_preset())

        len_hdr = tk.Frame(rand_tab, bg=colors["surface"])
        len_hdr.pack(fill="x")
        tk.Label(len_hdr, text="Length", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            side="left"
        )
        self._len_label = tk.Label(
            len_hdr, text="20", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 10, "bold")
        )
        self._len_label.pack(side="right")

        tk.Scale(
            rand_tab,
            from_=8,
            to=64,
            orient="horizontal",
            variable=self._length_var,
            showvalue=False,
            bg=colors["surface"],
            fg=colors["text"],
            troughcolor=colors["input"],
            activebackground=colors["accent"],
            highlightthickness=0,
            command=lambda _v: self._regenerate(),
        ).pack(fill="x", pady=(2, 8))

        checks = tk.Frame(rand_tab, bg=colors["surface"])
        checks.pack(fill="x", pady=(0, 8))
        opts = [
            ("Uppercase Letters (A-Z)", self._upper_var),
            ("Lowercase Letters (a-z)", self._lower_var),
            ("Numbers (0-9)", self._digits_var),
            ("Special Symbols (!@#$...)", self._symbols_var),
            ("Other / Extended (§±°€£¥•¿)", self._extended_var),
            ("Exclude Ambiguous (0Ol1I|)", self._ambiguous_var),
        ]
        for idx, (lbl, var) in enumerate(opts):
            tk.Checkbutton(
                checks,
                text=lbl,
                variable=var,
                command=self._regenerate,
                bg=colors["surface"],
                fg=colors["text"],
                selectcolor=colors["input"],
                activebackground=colors["surface"],
                activeforeground=colors["text"],
                font=("Segoe UI", 9),
            ).grid(row=idx // 2, column=idx % 2, sticky="w", padx=(0, 12), pady=2)

        custom_row = tk.Frame(rand_tab, bg=colors["surface"])
        custom_row.pack(fill="x", pady=(4, 8))
        tk.Label(
            custom_row, text="Custom Extra Chars:", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)
        ).pack(side="left", padx=(0, 8))
        tk.Entry(
            custom_row,
            textvariable=self._custom_var,
            bg=colors["input"],
            fg=colors["text"],
            insertbackground=colors["text"],
            relief="flat",
            font=("Consolas", 10),
        ).pack(side="left", fill="x", expand=True, ipady=4)
        self._custom_var.trace_add("write", lambda *_: self._regenerate())

        min_row = tk.Frame(rand_tab, bg=colors["surface"])
        min_row.pack(fill="x")
        tk.Label(min_row, text="Min Digits:", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            side="left", padx=(0, 4)
        )
        tk.Spinbox(
            min_row,
            from_=0,
            to=10,
            width=4,
            textvariable=self._min_digits_var,
            command=self._regenerate,
            bg=colors["input"],
            fg=colors["text"],
            buttonbackground=colors["surface_alt"],
            relief="flat",
        ).pack(side="left", padx=(0, 16))
        tk.Label(min_row, text="Min Symbols:", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            side="left", padx=(0, 4)
        )
        tk.Spinbox(
            min_row,
            from_=0,
            to=10,
            width=4,
            textvariable=self._min_symbols_var,
            command=self._regenerate,
            bg=colors["input"],
            fg=colors["text"],
            buttonbackground=colors["surface_alt"],
            relief="flat",
        ).pack(side="left")

        # Tab 2: Memorable Passphrase
        phrase_tab = tk.Frame(self._tabs, bg=colors["surface"], padx=10, pady=10)
        self._tabs.add(phrase_tab, text="  Memorable Passphrase  ")

        w_hdr = tk.Frame(phrase_tab, bg=colors["surface"])
        w_hdr.pack(fill="x")
        tk.Label(w_hdr, text="Word Count", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            side="left"
        )
        self._words_label = tk.Label(
            w_hdr, text="5 words", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 10, "bold")
        )
        self._words_label.pack(side="right")

        tk.Scale(
            phrase_tab,
            from_=3,
            to=10,
            orient="horizontal",
            variable=self._words_var,
            showvalue=False,
            bg=colors["surface"],
            fg=colors["text"],
            troughcolor=colors["input"],
            activebackground=colors["accent"],
            highlightthickness=0,
            command=lambda _v: self._regenerate(),
        ).pack(fill="x", pady=(2, 12))

        sep_row = tk.Frame(phrase_tab, bg=colors["surface"])
        sep_row.pack(fill="x", pady=(0, 10))
        tk.Label(sep_row, text="Separator:", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            side="left", padx=(0, 8)
        )
        sep_combo = ttk.Combobox(
            sep_row, textvariable=self._sep_var, values=("-", "_", ".", " ", "/", "+"), state="readonly", width=8
        )
        sep_combo.pack(side="left")
        sep_combo.bind("<<ComboboxSelected>>", lambda _e: self._regenerate())

        for lbl, var in (
            ("Capitalize Words", self._cap_var),
            ("Include Random Number", self._phrase_num_var),
            ("Include Special Symbol", self._phrase_sym_var),
        ):
            tk.Checkbutton(
                phrase_tab,
                text=lbl,
                variable=var,
                command=self._regenerate,
                bg=colors["surface"],
                fg=colors["text"],
                selectcolor=colors["input"],
                activebackground=colors["surface"],
                activeforeground=colors["text"],
                font=("Segoe UI", 9),
            ).pack(anchor="w", pady=3)

        btn_row = tk.Frame(card, bg=colors["surface"])
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Regenerate", command=self._regenerate).pack(side="left", padx=(0, 6))
        ttk.Button(btn_row, text="Copy", command=self._copy).pack(side="left", padx=(0, 6))
        if self._on_use is not None:
            ttk.Button(btn_row, text="Use Password", style="Accent.TButton", command=self._use).pack(side="right")
        else:
            ttk.Button(btn_row, text="Close", command=self.destroy).pack(side="right")

        self._regenerate()
        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)

    def _apply_preset(self) -> None:
        name = self._policy_var.get()
        pol = SITE_POLICY_PRESETS.get(name)
        if pol is None:
            return
        self._length_var.set(pol.length)
        self._upper_var.set(pol.use_upper)
        self._lower_var.set(pol.use_lower)
        self._digits_var.set(pol.use_digits)
        self._symbols_var.set(pol.use_symbols)
        self._extended_var.set(pol.use_extended)
        self._ambiguous_var.set(pol.exclude_ambiguous)
        self._min_digits_var.set(pol.min_digits)
        self._min_symbols_var.set(pol.min_symbols)
        self._regenerate()

    def _regenerate(self) -> None:
        tab_index = self._tabs.index(self._tabs.select())
        if tab_index == 0:
            pol = SITE_POLICY_PRESETS.get(self._policy_var.get())
            length = self._length_var.get()
            self._len_label.configure(text=str(length))
            try:
                if pol and length == pol.length and not self._custom_var.get():
                    pwd = generate_from_policy(pol)
                else:
                    pwd = generate_password(
                        length=length,
                        use_upper=self._upper_var.get(),
                        use_lower=self._lower_var.get(),
                        use_digits=self._digits_var.get(),
                        use_symbols=self._symbols_var.get(),
                        use_extended=self._extended_var.get(),
                        custom_chars=self._custom_var.get(),
                        exclude_ambiguous=self._ambiguous_var.get(),
                        min_digits=self._min_digits_var.get(),
                        min_symbols=self._min_symbols_var.get(),
                    )
            except ValueError:
                self._lower_var.set(True)
                pwd = generate_password(length=max(8, length), use_lower=True, use_digits=True)
        else:
            words = self._words_var.get()
            self._words_label.configure(text=f"{words} words")
            pwd = generate_passphrase(
                word_count=words,
                separator=self._sep_var.get(),
                capitalize=self._cap_var.get(),
                include_number=self._phrase_num_var.get(),
                include_symbol=self._phrase_sym_var.get(),
            )

        self._preview_var.set(pwd)
        self._strength.update_password(pwd)

    def _copy(self) -> None:
        pwd = self._preview_var.get()
        if self._on_copy:
            self._on_copy(pwd)
        else:
            self.clipboard_clear()
            self.clipboard_append(pwd)

    def _use(self) -> None:
        if self._on_use:
            self._on_use(self._preview_var.get())
        self.destroy()


# ====================================================================== #
# 4. Vault MFA Setup (TOTP + Anti-Replay + QR + Recovery Codes) Dialog
# ====================================================================== #


class MFASetupDialog(tk.Toplevel):
    """Enable or disable TOTP MFA (compatible with Google/Microsoft Authenticator, Aegis, 2FAS)."""

    def __init__(
        self,
        parent: tk.Misc,
        vault: ShieldVault,
        colors: dict[str, str],
        on_changed: Callable[[str], None],
        on_copy_secret: Callable[[str, str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — Multi-Factor Authentication (MFA)")
        self.configure(bg=colors["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._colors = colors
        self._on_changed = on_changed
        self._on_copy_secret = on_copy_secret
        self._card = tk.Frame(self, bg=colors["surface"], padx=22, pady=18)
        self._card.pack(fill="both", expand=True, padx=14, pady=14)

        if self._vault.mfa_enabled:
            self._build_enabled_view()
        else:
            self._build_setup_view()

        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)

    def _clear_card(self) -> None:
        for child in self._card.winfo_children():
            child.destroy()

    def _build_enabled_view(self) -> None:
        c = self._colors
        self._clear_card()
        tk.Label(
            self._card, text="Vault MFA is Active (Anti-Replay Protected)", bg=c["surface"], fg=c["success"], font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", pady=(0, 6))
        tk.Label(
            self._card,
            text=(
                "Compatible with Microsoft Authenticator, Google Authenticator, Aegis, and 2FAS.\n"
                f"Unused one-time MFA recovery codes remaining: {self._vault.remaining_mfa_recovery_codes}\n"
                "Note: Phone numbers / SMS are intentionally NOT used as keys or bypasses."
            ),
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
            justify="left",
            wraplength=410,
        ).pack(anchor="w", pady=(0, 14))

        tk.Label(self._card, text="Confirm Master Password to Disable MFA:", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 4)
        )
        self._disable_pwd = tk.StringVar()
        tk.Entry(
            self._card,
            textvariable=self._disable_pwd,
            show="•",
            bg=c["input"],
            fg=c["text"],
            insertbackground=c["text"],
            relief="flat",
            font=("Segoe UI", 11),
            width=36,
        ).pack(fill="x", ipady=6, pady=(0, 8))

        self._err = tk.Label(self._card, text="", bg=c["surface"], fg=c["danger"], font=("Segoe UI", 9))
        self._err.pack(anchor="w", pady=(0, 10))

        btns = tk.Frame(self._card, bg=c["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="left")
        ttk.Button(btns, text="Disable MFA", style="Danger.TButton", command=self._disable_mfa).pack(side="right")

    def _disable_mfa(self) -> None:
        pwd = self._disable_pwd.get()
        if not pwd:
            self._err.configure(text="Enter your master password to confirm.")
            return
        try:
            self._vault.disable_mfa(pwd)
        except (InvalidPasswordError, VaultError) as exc:
            self._err.configure(text=str(exc))
            return
        self._on_changed("Vault MFA has been disabled.")
        self.destroy()

    def _build_setup_view(self) -> None:
        c = self._colors
        self._clear_card()
        self._secret = generate_totp_secret()
        uri = build_otpauth_uri(self._secret, account_name=self._vault.path.stem)

        tk.Label(
            self._card, text="Enable Vault TOTP MFA", bg=c["surface"], fg=c["text"], font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", pady=(0, 6))
        tk.Label(
            self._card,
            text="Scan with Google Authenticator, Microsoft Authenticator, Aegis, or 2FAS, then enter the 6-digit code.",
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
            wraplength=400,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        matrix = build_qr_matrix(uri)
        if matrix:
            cell = 5
            size = len(matrix) * cell
            canvas = tk.Canvas(self._card, width=size, height=size, bg="#ffffff", highlightthickness=0)
            canvas.pack(pady=(0, 10))
            for r, row in enumerate(matrix):
                for col, filled in enumerate(row):
                    if filled:
                        canvas.create_rectangle(
                            col * cell, r * cell, (col + 1) * cell, (r + 1) * cell, fill="#000000", outline=""
                        )

        sec_row = tk.Frame(self._card, bg=c["input"], padx=10, pady=6)
        sec_row.pack(fill="x", pady=(0, 10))
        tk.Label(sec_row, text=f"Secret: {self._secret}", bg=c["input"], fg=c["text"], font=("Consolas", 9)).pack(
            side="left", fill="x", expand=True
        )
        def copy_totp_sec() -> None:
            if self._on_copy_secret:
                self._on_copy_secret(self._secret, "TOTP Secret")
            else:
                self.clipboard_clear()
                self.clipboard_append(self._secret)

        ttk.Button(sec_row, text="Copy", command=copy_totp_sec).pack(side="right")

        tk.Label(self._card, text="Enter 6-Digit Verification Code:", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 4)
        )
        self._code_var = tk.StringVar()
        code_entry = tk.Entry(
            self._card,
            textvariable=self._code_var,
            bg=c["input"],
            fg=c["text"],
            insertbackground=c["text"],
            relief="flat",
            font=("Consolas", 14),
            justify="center",
            width=14,
        )
        code_entry.pack(ipady=6, pady=(0, 8))
        code_entry.focus_set()

        self._err = tk.Label(self._card, text="", bg=c["surface"], fg=c["danger"], font=("Segoe UI", 9))
        self._err.pack(anchor="w", pady=(0, 10))

        btns = tk.Frame(self._card, bg=c["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")
        ttk.Button(btns, text="Verify & Enable MFA", style="Accent.TButton", command=self._verify_enable).pack(
            side="right"
        )
        code_entry.bind("<Return>", lambda _e: self._verify_enable())

    def _verify_enable(self) -> None:
        code = self._code_var.get().strip()
        try:
            recovery_codes = self._vault.enable_mfa(self._secret, code)
        except (InvalidMFACodeError, ValueError, VaultError) as exc:
            self._err.configure(text=str(exc))
            return
        self._on_changed("Vault MFA enabled with anti-replay protection.")
        self._show_recovery_codes(recovery_codes)

    def _show_recovery_codes(self, codes: list[str]) -> None:
        c = self._colors
        self._clear_card()
        tk.Label(
            self._card, text="MFA Enabled — Save One-Time Codes", bg=c["surface"], fg=c["success"], font=("Segoe UI", 13, "bold")
        ).pack(anchor="w", pady=(0, 6))
        tk.Label(
            self._card,
            text="Each code can bypass MFA once if you lose your authenticator app. Store offline.",
            bg=c["surface"],
            fg=c["warning"],
            font=("Segoe UI", 9),
            wraplength=400,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        formatted = "\n".join(codes)
        box = tk.Text(
            self._card, height=9, width=36, bg=c["input"], fg=c["text"], font=("Consolas", 11), relief="flat", padx=12, pady=8
        )
        box.insert("1.0", formatted)
        box.configure(state="disabled")
        box.pack(fill="x", pady=(0, 12))

        def copy_codes() -> None:
            if self._on_copy_secret:
                self._on_copy_secret(formatted, "MFA Recovery Codes")
            else:
                self.clipboard_clear()
                self.clipboard_append(formatted)

        btns = tk.Frame(self._card, bg=c["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Copy All (Auto-Clears)", command=copy_codes).pack(side="left")
        ttk.Button(btns, text="Done", style="Accent.TButton", command=self.destroy).pack(side="right")


# ====================================================================== #
# 5. E2EE Sync & X25519 Entry Sharing Dialog
# ====================================================================== #


class E2EESyncShareDialog(tk.Toplevel):
    """Zero-Knowledge E2EE Sync + X25519 / Argon2id-Passphrase Entry Sharing."""

    def __init__(
        self,
        parent: tk.Misc,
        vault: ShieldVault,
        colors: dict[str, str],
        on_vault_changed: Callable[[str], None],
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — E2EE Sync & Secure Entry Sharing")
        self.configure(bg=colors["bg"])
        self.geometry("690x560")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._colors = colors
        self._on_vault_changed = on_vault_changed

        wrap = tk.Frame(self, bg=colors["bg"], padx=14, pady=14)
        wrap.pack(fill="both", expand=True)

        tabs = ttk.Notebook(wrap)
        tabs.pack(fill="both", expand=True)
        self._build_sync_tab(tabs)
        self._build_share_tab(tabs)

        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)

    def _build_sync_tab(self, tabs: ttk.Notebook) -> None:
        c = self._colors
        tab = tk.Frame(tabs, bg=c["surface"], padx=18, pady=16)
        tabs.add(tab, text="  Zero-Knowledge E2EE Sync  ")

        tk.Label(tab, text="Zero-Knowledge Multi-Device Sync", bg=c["surface"], fg=c["text"], font=("Segoe UI", 13, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        tk.Label(
            tab,
            text=(
                "Sync your vault via Google Drive, OneDrive, Dropbox, or USB without trusting the storage provider. "
                "Records are decrypted & conflict-merged locally and written back as Argon2id + AES-256-GCM ciphertext."
            ),
            bg=c["surface"],
            fg=c["muted"],
            font=("Segoe UI", 9),
            wraplength=600,
            justify="left",
        ).pack(anchor="w", pady=(0, 14))

        tk.Label(tab, text="Sync File (.shield.enc)", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 4)
        )
        self._sync_path_var = tk.StringVar(value=self._vault.sync_path)
        prow = tk.Frame(tab, bg=c["surface"])
        prow.pack(fill="x", pady=(0, 10))
        tk.Entry(
            prow, textvariable=self._sync_path_var, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 10)
        ).pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 6))
        ttk.Button(prow, text="Browse...", command=self._browse_sync).pack(side="left", padx=(0, 4))
        ttk.Button(prow, text="Google Drive", command=self._pick_gdrive).pack(side="left")

        tk.Label(tab, text="Confirm Master Password:", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(6, 4)
        )
        self._sync_pwd = tk.StringVar()
        tk.Entry(
            tab, textvariable=self._sync_pwd, show="•", bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 11)
        ).pack(fill="x", ipady=6, pady=(0, 12))

        self._sync_status = tk.Label(tab, text="", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9), wraplength=600, justify="left")
        self._sync_status.pack(anchor="w", pady=(0, 14))

        ttk.Button(tab, text="Sync & Merge Now (E2EE)", style="Accent.TButton", command=self._run_sync).pack(anchor="w")

    def _browse_sync(self) -> None:
        chosen = filedialog.asksaveasfilename(
            title="Select or Create E2EE Sync Vault",
            defaultextension=".enc",
            initialfile="SHIELD_E2EE_Sync.shield.enc",
            filetypes=[("S.H.I.E.L.D. Encrypted Sync", "*.enc")],
            parent=self,
            confirmoverwrite=False,
        )
        if chosen:
            self._sync_path_var.set(chosen)

    def _pick_gdrive(self) -> None:
        folders = detect_google_drive_folders()
        if folders:
            self._sync_path_var.set(str(folders[0] / "SHIELD_E2EE_Sync.shield.enc"))
            self._sync_status.configure(text=f"Detected Google Drive: {folders[0]}", fg=self._colors["success"])
        else:
            folder = filedialog.askdirectory(title="Select Your Google Drive Folder", parent=self)
            if folder:
                self._sync_path_var.set(str(Path(folder) / "SHIELD_E2EE_Sync.shield.enc"))

    def _run_sync(self) -> None:
        target = self._sync_path_var.get().strip()
        pwd = self._sync_pwd.get()
        if not target or not pwd:
            self._sync_status.configure(text="Provide both sync path and master password.", fg=self._colors["danger"])
            return
        try:
            stats = self._vault.sync_with_remote(target, pwd)
        except Exception as exc:
            self._sync_status.configure(text=f"Sync failed: {exc}", fg=self._colors["danger"])
            return
        finally:
            self._sync_pwd.set("")
        msg = (
            f"E2EE Sync complete! Added: {stats['added_local']}, Updated: {stats['updated_local']}, "
            f"Removed: {stats['removed_local']} (Total: {stats['total_entries']})."
        )
        self._sync_status.configure(text=msg, fg=self._colors["success"])
        self._on_vault_changed(msg)

    def _build_share_tab(self, tabs: ttk.Notebook) -> None:
        c = self._colors
        tab = tk.Frame(tabs, bg=c["surface"], padx=18, pady=14)
        tabs.add(tab, text="  E2EE Entry Sharing (X25519)  ")

        tk.Label(tab, text="Your X25519 Public Key:", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 3)
        )
        pk_row = tk.Frame(tab, bg=c["input"], padx=8, pady=5)
        pk_row.pack(fill="x", pady=(0, 10))
        tk.Label(pk_row, text=self._vault.public_key, bg=c["input"], fg=c["text"], font=("Consolas", 9)).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            pk_row, text="Copy", command=lambda: (self.clipboard_clear(), self.clipboard_append(self._vault.public_key))
        ).pack(side="right")

        tk.Label(tab, text="Encrypt & Share Credential", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        entries = self._vault.list_entries()
        self._choices = {f"{e.title} ({e.username or e.entry_type})": e.id for e in entries}
        self._share_entry_var = tk.StringVar(value=next(iter(self._choices), ""))
        self._share_mode_var = tk.StringVar(value="Public Key (X25519)")
        self._share_target_var = tk.StringVar()

        top = tk.Frame(tab, bg=c["surface"])
        top.pack(fill="x", pady=(0, 6))
        ttk.Combobox(top, textvariable=self._share_entry_var, values=list(self._choices.keys()), state="readonly", width=34).pack(
            side="left", fill="x", expand=True, padx=(0, 6)
        )
        ttk.Combobox(
            top, textvariable=self._share_mode_var, values=("Public Key (X25519)", "One-Time Passphrase"), state="readonly", width=20
        ).pack(side="left")

        trow = tk.Frame(tab, bg=c["surface"])
        trow.pack(fill="x", pady=(0, 8))
        tk.Entry(
            trow, textvariable=self._share_target_var, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Consolas", 9)
        ).pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 6))
        ttk.Button(trow, text="Encrypt & Copy Packet", style="Accent.TButton", command=self._encrypt_share).pack(side="right")

        tk.Frame(tab, bg=c["border"], height=1).pack(fill="x", pady=(4, 10))
        tk.Label(tab, text="Receive & Decrypt E2EE Packet", bg=c["surface"], fg=c["text"], font=("Segoe UI", 11, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        self._packet_text = tk.Text(
            tab, height=4, bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Consolas", 9), wrap="char", padx=6, pady=5
        )
        self._packet_text.pack(fill="x", pady=(0, 6))

        drow = tk.Frame(tab, bg=c["surface"])
        drow.pack(fill="x", pady=(0, 6))
        tk.Label(drow, text="Passphrase (if PW packet):", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 8)).pack(
            side="left", padx=(0, 6)
        )
        self._dec_pw = tk.StringVar()
        tk.Entry(
            drow, textvariable=self._dec_pw, show="•", bg=c["input"], fg=c["text"], insertbackground=c["text"], relief="flat", font=("Segoe UI", 9), width=22
        ).pack(side="left", ipady=4)
        ttk.Button(drow, text="Decrypt & Import", style="Accent.TButton", command=self._decrypt_share).pack(side="right")

        self._share_status = tk.Label(tab, text="", bg=c["surface"], fg=c["muted"], font=("Segoe UI", 9), wraplength=600, justify="left")
        self._share_status.pack(anchor="w", pady=(4, 0))

    def _encrypt_share(self) -> None:
        eid = self._choices.get(self._share_entry_var.get())
        target = self._share_target_var.get().strip()
        if not eid or not target:
            self._share_status.configure(text="Select an entry and provide a recipient public key or passphrase.", fg=self._colors["danger"])
            return
        try:
            if self._share_mode_var.get().startswith("Public"):
                packet = self._vault.share_entry_for_public_key(eid, target)
            else:
                packet = self._vault.share_entry_with_passphrase(eid, target)
        except (E2EEError, ValueError, KeyError) as exc:
            self._share_status.configure(text=str(exc), fg=self._colors["danger"])
            return
        self.clipboard_clear()
        self.clipboard_append(packet)
        self._packet_text.delete("1.0", "end")
        self._packet_text.insert("1.0", packet)
        self._share_status.configure(text="Encrypted packet copied to clipboard!", fg=self._colors["success"])

    def _decrypt_share(self) -> None:
        token = self._packet_text.get("1.0", "end").strip()
        if not token:
            return
        pw = self._dec_pw.get()
        if token.startswith(SHARE_PW_PREFIX) and not pw:
            self._share_status.configure(text="Passphrase required for PW packets.", fg=self._colors["danger"])
            return
        try:
            entry = self._vault.import_e2ee_packet(token, passphrase=pw)
        except (E2EEError, ValueError) as exc:
            self._share_status.configure(text=str(exc), fg=self._colors["danger"])
            return
        self._dec_pw.set("")
        fp = self._vault.last_e2ee_sender_fingerprint
        msg = f"Verified & imported '{entry.title}' (Source Authenticity: {fp})."
        self._share_status.configure(text=msg, fg=self._colors["success"])
        self._on_vault_changed(msg)


# ====================================================================== #
# 6. Consent-Gated Google Password Manager Dialog
# ====================================================================== #


class GoogleVaultDialog(tk.Toplevel):
    """Consent-gated Google Password Manager links, CSV import/export, and Google Drive E2EE sync."""

    def __init__(
        self,
        parent: tk.Misc,
        vault: ShieldVault,
        colors: dict[str, str],
        on_vault_changed: Callable[[str], None],
        on_open_e2ee_sync: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — Google Password Manager Link (Consent-Gated)")
        self.configure(bg=colors["bg"])
        self.geometry("660x560")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._colors = colors
        self._on_vault_changed = on_vault_changed
        self._on_open_e2ee_sync = on_open_e2ee_sync
        self._consent_var = tk.BooleanVar(value=False)

        card = tk.Frame(self, bg=colors["surface"], padx=22, pady=18)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        tk.Label(card, text="Google Password Manager Integration", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 14, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        tk.Label(
            card,
            text=(
                "Zero-Trust Consent Notice:\n"
                "Google does not expose a direct third-party API to read/write Google Password Manager. "
                "S.H.I.E.L.D. never accesses your Google account automatically. With your explicit consent below:\n"
                "  1. Open Google Password Manager / Password Checkup in your browser.\n"
                "  2. Import/Export official Google CSV files (with optional secure overwrite & shred).\n"
                "  3. Sync your Argon2id + AES-256-GCM encrypted vault via Google Drive."
            ),
            bg=colors["input"],
            fg=colors["muted"],
            font=("Segoe UI", 9),
            justify="left",
            wraplength=580,
            padx=12,
            pady=10,
        ).pack(fill="x", pady=(0, 12))

        tk.Checkbutton(
            card,
            text="I understand and consent to connecting with Google Password Manager / Google Drive.",
            variable=self._consent_var,
            command=self._toggle_consent,
            bg=colors["surface"],
            fg=colors["text"],
            selectcolor=colors["input"],
            activebackground=colors["surface"],
            activeforeground=colors["text"],
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w", pady=(0, 14))

        self._btns: list[ttk.Button] = []

        tk.Label(card, text="1. Quick Browser Links", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        lrow = tk.Frame(card, bg=colors["surface"])
        lrow.pack(fill="x", pady=(0, 14))
        for lbl, url in (
            ("Google Password Manager", GOOGLE_PASSWORDS_URL),
            ("Google Password Checkup", GOOGLE_CHECKUP_URL),
            ("Google Account Security", GOOGLE_SECURITY_URL),
        ):
            b = ttk.Button(lrow, text=lbl, command=lambda u=url: webbrowser.open(u), state="disabled")
            b.pack(side="left", padx=(0, 6))
            self._btns.append(b)

        tk.Label(card, text="2. Official Google CSV Import / Export", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 6)
        )
        crow = tk.Frame(card, bg=colors["surface"])
        crow.pack(fill="x", pady=(0, 14))
        b_imp = ttk.Button(crow, text="Import Google CSV...", style="Accent.TButton", command=self._import_csv, state="disabled")
        b_imp.pack(side="left", padx=(0, 8))
        b_exp = ttk.Button(crow, text="Export to Google CSV (Adaptive Auth)...", command=self._export_csv, state="disabled")
        b_exp.pack(side="left")
        self._btns.extend([b_imp, b_exp])

        tk.Label(card, text="3. E2EE Sync via Google Drive", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        detected = detect_google_drive_folders()
        hint = f"Detected Google Drive: {detected[0]}" if detected else "No local Google Drive folder auto-detected (browse manually)."
        tk.Label(card, text=hint, bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 6))
        b_gd = ttk.Button(card, text="Open Google Drive E2EE Sync...", command=self._open_sync, state="disabled")
        b_gd.pack(anchor="w", pady=(0, 12))
        self._btns.append(b_gd)

        self._status = tk.Label(
            card, text="Check the consent box above to enable actions.", bg=colors["surface"], fg=colors["warning"], font=("Segoe UI", 9), wraplength=580, justify="left"
        )
        self._status.pack(anchor="w", pady=(0, 8))

        ttk.Button(card, text="Close", command=self.destroy).pack(anchor="e")
        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)

    def _toggle_consent(self) -> None:
        st = "normal" if self._consent_var.get() else "disabled"
        for b in self._btns:
            b.configure(state=st)
        self._status.configure(
            text="Consent confirmed." if st == "normal" else "Check the consent box above to enable actions.",
            fg=self._colors["success"] if st == "normal" else self._colors["warning"],
        )

    def _import_csv(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Google Password Manager CSV", filetypes=[("CSV Files", "*.csv")], parent=self
        )
        if not path:
            return
        try:
            items, skipped = parse_google_passwords_csv(path)
        except Exception as exc:
            messagebox.showerror("Import Error", str(exc), parent=self)
            return
        if not items:
            messagebox.showinfo("Empty CSV", "No password rows found.", parent=self)
            return
        if not messagebox.askyesno(
            "Import Google Passwords",
            f"Import {len(items)} credentials into your per-record encrypted S.H.I.E.L.D. vault? (Skipped {skipped} blank rows)",
            parent=self,
        ):
            return
        imported, dupes = self._vault.import_google_items(items, skip_duplicates=True)
        msg = f"Imported {imported} entries from Google CSV ({dupes} duplicates skipped)."
        self._status.configure(text=msg, fg=self._colors["success"])
        self._on_vault_changed(msg)
        if messagebox.askyesno(
            "Securely Shred Plaintext CSV?",
            f"Overwrite and permanently delete unencrypted '{Path(path).name}' from disk now?",
            parent=self,
        ):
            secure_delete_file(path)
            self._status.configure(text=msg + " Plaintext CSV securely shredded.", fg=self._colors["success"])

    def _export_csv(self) -> None:
        ok, _pwd, _mfa = prompt_adaptive_reauth(self, self._vault, "export_google_csv", self._colors)
        if not ok:
            return
        if not messagebox.askyesno(
            "Security Warning — Unencrypted CSV",
            "Google CSV exports are UNENCRYPTED plaintext. Import into passwords.google.com immediately and delete the file.\n\nContinue?",
            icon="warning",
            parent=self,
        ):
            return
        dest = filedialog.asksaveasfilename(
            title="Export to Google CSV",
            defaultextension=".csv",
            initialfile="shield_for_google.csv",
            filetypes=[("CSV Files", "*.csv")],
            parent=self,
        )
        if not dest:
            return
        out = export_google_passwords_csv(self._vault.list_entries(), dest)
        self._vault.record_credential_event("export_google_csv", severity="alert")
        self._status.configure(text=f"Exported to {out.name}. Delete immediately after importing to Google!", fg=self._colors["warning"])

    def _open_sync(self) -> None:
        self.destroy()
        self._on_open_e2ee_sync()


# ====================================================================== #
# 7. Change Master Password Dialog
# ====================================================================== #


class ChangeMasterPasswordDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        vault: ShieldVault,
        colors: dict[str, str],
        on_changed: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self.title("S.H.I.E.L.D. — Rotate Master Password")
        self.configure(bg=colors["bg"])
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._vault = vault
        self._on_changed = on_changed
        self._cur = tk.StringVar()
        self._new = tk.StringVar()
        self._conf = tk.StringVar()

        card = tk.Frame(self, bg=colors["surface"], padx=22, pady=18)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        tk.Label(card, text="Rotate Master Password (Argon2id)", bg=colors["surface"], fg=colors["text"], font=("Segoe UI", 13, "bold")).pack(
            anchor="w", pady=(0, 12)
        )
        for lbl, var in (
            ("Current Master Password", self._cur),
            ("New Master Password (min 8 chars)", self._new),
        ):
            tk.Label(card, text=lbl, bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 3))
            tk.Entry(
                card, textvariable=var, show="•", bg=colors["input"], fg=colors["text"], insertbackground=colors["text"], relief="flat", font=("Segoe UI", 11), width=34
            ).pack(fill="x", ipady=6, pady=(0, 8))

        bar = StrengthBar(card, colors=colors)
        bar.pack(fill="x", pady=(0, 10))
        self._new.trace_add("write", lambda *_: bar.update_password(self._new.get()))

        tk.Label(card, text="Confirm New Master Password", bg=colors["surface"], fg=colors["muted"], font=("Segoe UI", 9)).pack(
            anchor="w", pady=(0, 3)
        )
        tk.Entry(
            card, textvariable=self._conf, show="•", bg=colors["input"], fg=colors["text"], insertbackground=colors["text"], relief="flat", font=("Segoe UI", 11)
        ).pack(fill="x", ipady=6, pady=(0, 8))

        self._err = tk.Label(card, text="", bg=colors["surface"], fg=colors["danger"], font=("Segoe UI", 9), wraplength=340)
        self._err.pack(anchor="w", pady=(0, 10))

        btns = tk.Frame(card, bg=colors["surface"])
        btns.pack(fill="x")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left")
        ttk.Button(btns, text="Update Master Password", style="Accent.TButton", command=self._submit).pack(side="right")

        self.bind("<Return>", lambda _e: self._submit())
        self.bind("<Escape>", lambda _e: self.destroy())
        center_window(self, parent)

    def _submit(self) -> None:
        if len(self._new.get()) < 8:
            self._err.configure(text="New master password must be at least 8 characters.")
            return
        if self._new.get() != self._conf.get():
            self._err.configure(text="New passwords do not match.")
            return
        try:
            self._vault.change_master_password(self._cur.get(), self._new.get())
        except Exception as exc:
            self._err.configure(text=str(exc))
            return
        self._on_changed()
        self.destroy()
