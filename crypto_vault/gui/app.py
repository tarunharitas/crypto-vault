"""Modern Desktop Graphical Interface for CryptoVault."""
from __future__ import annotations

import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import pyperclip

from crypto_vault.crypto.cipher import decrypt_file, encrypt_file
from crypto_vault.crypto.integrity import create_signature, verify_signature
from crypto_vault.exceptions import AuthenticationError
from crypto_vault.gui.password_generator import generate_password, get_strength_info
from crypto_vault.vault import Vault

# Color Palette (Obsidian Cyber-Fintech)
BG_DARK = "#0B0F19"
BG_SIDEBAR = "#0F172A"
BG_CARD = "#1E293B"
BG_CARD_HOVER = "#243047"
BG_INPUT = "#0B132B"
BORDER_COLOR = "#334155"
ACCENT_EMERALD = "#10B981"
ACCENT_EMERALD_HOVER = "#059669"
ACCENT_CYAN = "#06B6D4"
ACCENT_CYAN_HOVER = "#0891B2"
ACCENT_BLUE = "#3B82F6"
TEXT_PRIMARY = "#F8FAFC"
TEXT_SECONDARY = "#94A3B8"
TEXT_MUTED = "#64748B"
DANGER = "#EF4444"
DANGER_HOVER = "#DC2626"
SUCCESS = "#10B981"
WARNING = "#F59E0B"

FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "Helvetica"
FONT_TITLE = (FONT_FAMILY, 15, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 11, "bold")
FONT_BODY = (FONT_FAMILY, 10)
FONT_BOLD = (FONT_FAMILY, 10, "bold")
FONT_SMALL = (FONT_FAMILY, 9)
FONT_MONO = ("Consolas" if sys.platform == "win32" else "Courier", 10)


class ModernButton(tk.Button):
    """Custom flat rounded-feel button with hover state."""
    def __init__(self, master, text="", command=None, bg_color=ACCENT_EMERALD, hover_color=ACCENT_EMERALD_HOVER,
                 text_color="#FFFFFF", font=FONT_BOLD, padx=12, pady=6, cursor="hand2", **kwargs):
        super().__init__(
            master,
            text=text,
            command=command,
            bg=bg_color,
            fg=text_color,
            activebackground=hover_color,
            activeforeground=text_color,
            bd=0,
            relief="flat",
            font=font,
            padx=padx,
            pady=pady,
            cursor=cursor,
            **kwargs
        )
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.bind("<Enter>", lambda e: self.configure(bg=self.hover_color))
        self.bind("<Leave>", lambda e: self.configure(bg=self.bg_color))


class CryptoVaultGUI(tk.Tk):
    def __init__(self, db_path: Path | None = None):
        super().__init__()
        self.title("CryptoVault - Authenticated Local Security")
        self.geometry("1020x680")
        self.minsize(900, 600)
        self.configure(bg=BG_DARK)

        # State
        self.db_path = db_path or Path(os.environ.get("CRYPTOVAULT_DB", "vault.db"))
        self.vault: Vault | None = None
        self.unlocked_key: bytes | None = None
        self.active_screen: str = "vault"
        self.all_credentials: list[dict] = []

        self._configure_styles()
        self._build_main_layout()
        self._check_vault_status()

    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Scrollbar
        style.configure(
            "Vertical.TScrollbar",
            background=BG_CARD,
            troughcolor=BG_DARK,
            bordercolor=BG_DARK,
            arrowcolor=TEXT_SECONDARY,
            relief="flat",
        )
        style.map("Vertical.TScrollbar", background=[("active", ACCENT_CYAN)])

        # Notebook
        style.configure(
            "TNotebook",
            background=BG_DARK,
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=BG_SIDEBAR,
            foreground=TEXT_SECONDARY,
            padding=[16, 8],
            font=FONT_BOLD,
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", BG_CARD), ("active", BG_CARD_HOVER)],
            foreground=[("selected", ACCENT_CYAN), ("active", TEXT_PRIMARY)],
        )

    def _build_main_layout(self):
        # Master container
        self.container = tk.Frame(self, bg=BG_DARK)
        self.container.pack(fill="both", expand=True)

        # Overlay frame for locked / init state
        self.lock_overlay = tk.Frame(self.container, bg=BG_DARK)
        self.lock_overlay.pack(fill="both", expand=True)

        # Dashboard frame (once unlocked)
        self.dashboard = tk.Frame(self.container, bg=BG_DARK)

        # Sidebar in dashboard
        self.sidebar = tk.Frame(self.dashboard, bg=BG_SIDEBAR, width=230)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Main content in dashboard
        self.content_area = tk.Frame(self.dashboard, bg=BG_DARK)
        self.content_area.pack(side="right", fill="both", expand=True)

        self._build_sidebar()
        self._build_screens()

    def _build_sidebar(self):
        # Logo & App Title
        header_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR)
        header_frame.pack(fill="x", padx=18, pady=(24, 20))

        title_lbl = tk.Label(
            header_frame,
            text="CRYPTOVAULT",
            font=(FONT_FAMILY, 14, "bold"),
            fg=ACCENT_CYAN,
            bg=BG_SIDEBAR,
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            header_frame,
            text="Zero-Knowledge Security",
            font=FONT_SMALL,
            fg=TEXT_MUTED,
            bg=BG_SIDEBAR,
        )
        sub_lbl.pack(anchor="w")

        sep = tk.Frame(self.sidebar, bg=BORDER_COLOR, height=1)
        sep.pack(fill="x", padx=16, pady=(0, 16))

        # Navigation buttons
        self.nav_buttons = {}
        nav_items = [
            ("vault", "🔑  Credentials Vault"),
            ("files", "🔐  File Encryption"),
            ("integrity", "🔏  File Integrity (HMAC)"),
            ("settings", "⚙️  Settings & Security"),
        ]

        for screen_id, text in nav_items:
            btn = tk.Button(
                self.sidebar,
                text=text,
                anchor="w",
                padx=16,
                pady=10,
                font=FONT_BOLD,
                bg=BG_SIDEBAR,
                fg=TEXT_SECONDARY,
                activebackground=BG_CARD,
                activeforeground=TEXT_PRIMARY,
                bd=0,
                relief="flat",
                cursor="hand2",
                command=lambda s=screen_id: self.switch_screen(s),
            )
            btn.pack(fill="x", padx=10, pady=3)
            self.nav_buttons[screen_id] = btn

        # Bottom section: Status & Lock button
        bottom_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR)
        bottom_frame.pack(side="bottom", fill="x", padx=16, pady=20)

        self.status_badge = tk.Label(
            bottom_frame,
            text="● UNLOCKED",
            font=FONT_SMALL,
            fg=ACCENT_EMERALD,
            bg=BG_SIDEBAR,
        )
        self.status_badge.pack(anchor="w", pady=(0, 10))

        lock_btn = ModernButton(
            bottom_frame,
            text="🔒 Lock Vault",
            bg_color=BG_CARD,
            hover_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            command=self.lock_vault,
            font=FONT_BOLD,
        )
        lock_btn.pack(fill="x")

    def _build_screens(self):
        # Dictionary to hold content views
        self.views = {
            "vault": tk.Frame(self.content_area, bg=BG_DARK),
            "files": tk.Frame(self.content_area, bg=BG_DARK),
            "integrity": tk.Frame(self.content_area, bg=BG_DARK),
            "settings": tk.Frame(self.content_area, bg=BG_DARK),
        }

        self._build_vault_view(self.views["vault"])
        self._build_files_view(self.views["files"])
        self._build_integrity_view(self.views["integrity"])
        self._build_settings_view(self.views["settings"])

    def _check_vault_status(self):
        """Check if vault database exists and is initialized."""
        try:
            v = Vault(self.db_path)
            salt = v.db.get_meta("salt")
            v.close()
            is_initialized = salt is not None
        except Exception:
            is_initialized = False

        self._show_lock_overlay(is_initialized)

    def _show_lock_overlay(self, is_initialized: bool):
        # Clear lock overlay
        for w in self.lock_overlay.winfo_children():
            w.destroy()

        self.dashboard.pack_forget()
        self.lock_overlay.pack(fill="both", expand=True)

        card = tk.Frame(self.lock_overlay, bg=BG_CARD, padx=40, pady=36, highlightbackground=BORDER_COLOR, highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center", width=460)

        # Icon and title
        icon_lbl = tk.Label(card, text="🛡️", font=(FONT_FAMILY, 32), bg=BG_CARD, fg=ACCENT_CYAN)
        icon_lbl.pack()

        title_txt = "Welcome to CryptoVault" if not is_initialized else "CryptoVault Locked"
        title = tk.Label(card, text=title_txt, font=FONT_TITLE, fg=TEXT_PRIMARY, bg=BG_CARD)
        title.pack(pady=(6, 4))

        sub_txt = "Create a master password to initialize your encrypted vault." if not is_initialized else "Enter master password to derive Argon2id encryption key."
        subtitle = tk.Label(card, text=sub_txt, font=FONT_SMALL, fg=TEXT_SECONDARY, bg=BG_CARD, wraplength=380, justify="center")
        subtitle.pack(pady=(0, 20))

        if not is_initialized:
            # Init mode: password + confirm
            pwd_lbl = tk.Label(card, text="Master Password", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD)
            pwd_lbl.pack(anchor="w")

            pwd_entry = tk.Entry(card, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY,
                                 insertbackground=TEXT_PRIMARY, bd=1, relief="solid", highlightthickness=1,
                                 highlightbackground=BORDER_COLOR)
            pwd_entry.pack(fill="x", pady=(4, 12), ipady=6)

            conf_lbl = tk.Label(card, text="Confirm Master Password", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD)
            conf_lbl.pack(anchor="w")

            conf_entry = tk.Entry(card, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY,
                                  insertbackground=TEXT_PRIMARY, bd=1, relief="solid", highlightthickness=1,
                                  highlightbackground=BORDER_COLOR)
            conf_entry.pack(fill="x", pady=(4, 16), ipady=6)

            # Strength label
            strength_lbl = tk.Label(card, text="Password Strength: None", font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_CARD)
            strength_lbl.pack(anchor="w", pady=(0, 16))

            def on_key_type(event):
                lbl, color, _pct = get_strength_info(pwd_entry.get())
                strength_lbl.configure(text=f"Password Strength: {lbl}", fg=color)

            pwd_entry.bind("<KeyRelease>", on_key_type)

            error_lbl = tk.Label(card, text="", font=FONT_SMALL, fg=DANGER, bg=BG_CARD)
            error_lbl.pack(pady=(0, 8))

            def do_init():
                p1 = pwd_entry.get()
                p2 = conf_entry.get()
                if not p1:
                    error_lbl.configure(text="Please enter a master password.")
                    return
                if p1 != p2:
                    error_lbl.configure(text="Passwords do not match.")
                    return

                try:
                    with Vault(self.db_path) as v:
                        v.initialize(p1)
                    self._show_lock_overlay(True)
                except Exception as exc:
                    error_lbl.configure(text=str(exc))

            init_btn = ModernButton(card, text="Initialize Vault (Argon2id)", command=do_init, bg_color=ACCENT_EMERALD, hover_color=ACCENT_EMERALD_HOVER)
            init_btn.pack(fill="x", ipady=4)
            pwd_entry.focus_set()
            conf_entry.bind("<Return>", lambda e: do_init())

        else:
            # Unlock mode
            pwd_lbl = tk.Label(card, text="Master Password", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD)
            pwd_lbl.pack(anchor="w")

            pwd_frame = tk.Frame(card, bg=BG_CARD)
            pwd_frame.pack(fill="x", pady=(4, 14))

            pwd_entry = tk.Entry(pwd_frame, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY,
                                 insertbackground=TEXT_PRIMARY, bd=1, relief="solid", highlightthickness=1,
                                 highlightbackground=BORDER_COLOR)
            pwd_entry.pack(side="left", fill="x", expand=True, ipady=6)

            show_var = tk.BooleanVar(value=False)
            def toggle_eye():
                if show_var.get():
                    pwd_entry.configure(show="●")
                    show_var.set(False)
                    eye_btn.configure(text="👁️")
                else:
                    pwd_entry.configure(show="")
                    show_var.set(True)
                    eye_btn.configure(text="🔒")

            eye_btn = tk.Button(pwd_frame, text="👁️", font=FONT_BODY, bg=BG_CARD_HOVER, fg=TEXT_SECONDARY,
                                bd=0, relief="flat", cursor="hand2", command=toggle_eye)
            eye_btn.pack(side="right", padx=(6, 0), ipady=4, ipadx=6)

            error_lbl = tk.Label(card, text="", font=FONT_SMALL, fg=DANGER, bg=BG_CARD)
            error_lbl.pack(pady=(0, 10))

            status_note = tk.Label(card, text="Argon2id key derivation uses 64 MiB RAM and 3 iterations.",
                                   font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_CARD)
            status_note.pack(pady=(0, 14))

            def do_unlock():
                p = pwd_entry.get()
                if not p:
                    error_lbl.configure(text="Password cannot be empty.")
                    return

                self.config(cursor="wait")
                self.update_idletasks()
                v = None
                try:
                    v = Vault(self.db_path)
                    key = v.unlock(p)
                    self.vault = v
                    self.unlocked_key = key
                    v = None  # ownership transferred to self.vault
                    self.config(cursor="")
                    self._show_dashboard()
                except AuthenticationError:
                    if v is not None:
                        v.close()
                    self.config(cursor="")
                    error_lbl.configure(text="Authentication failed: incorrect password.")
                except Exception as exc:
                    if v is not None:
                        v.close()
                    self.config(cursor="")
                    error_lbl.configure(text=f"Error: {exc}")

            unlock_btn = ModernButton(card, text="Unlock Vault", command=do_unlock, bg_color=ACCENT_CYAN, hover_color=ACCENT_CYAN_HOVER)
            unlock_btn.pack(fill="x", ipady=4)
            pwd_entry.focus_set()
            pwd_entry.bind("<Return>", lambda e: do_unlock())

    def _show_dashboard(self):
        self.lock_overlay.pack_forget()
        self.dashboard.pack(fill="both", expand=True)
        self.switch_screen("vault")
        self.refresh_credentials()

    def lock_vault(self):
        """Immediately discard derived key and close database."""
        self.unlocked_key = None
        if self.vault:
            self.vault.close()
            self.vault = None
        self._check_vault_status()

    def switch_screen(self, screen_id: str):
        self.active_screen = screen_id
        for s_id, btn in self.nav_buttons.items():
            if s_id == screen_id:
                btn.configure(bg=BG_CARD, fg=ACCENT_CYAN)
            else:
                btn.configure(bg=BG_SIDEBAR, fg=TEXT_SECONDARY)

        for s_id, view in self.views.items():
            if s_id == screen_id:
                view.pack(fill="both", expand=True)
            else:
                view.pack_forget()

        if screen_id == "vault":
            self.refresh_credentials()
        elif screen_id == "settings":
            self._update_settings_display()

    # ----------------------------------------------------
    # TOAST NOTIFICATION
    # ----------------------------------------------------
    def show_toast(self, message: str, color=ACCENT_EMERALD, duration=2500):
        toast = tk.Label(self, text=message, font=FONT_BOLD, fg="#FFFFFF", bg=color, padx=16, pady=8, relief="flat")
        toast.place(relx=0.5, rely=0.04, anchor="n")
        self.after(duration, toast.destroy)

    # ----------------------------------------------------
    # 1. VAULT VIEW
    # ----------------------------------------------------
    def _build_vault_view(self, parent: tk.Frame):
        # Top toolbar
        toolbar = tk.Frame(parent, bg=BG_DARK)
        toolbar.pack(fill="x", padx=24, pady=(20, 14))

        # Title + count badge
        title_box = tk.Frame(toolbar, bg=BG_DARK)
        title_box.pack(side="left")

        v_title = tk.Label(title_box, text="Credentials Vault", font=FONT_TITLE, fg=TEXT_PRIMARY, bg=BG_DARK)
        v_title.pack(side="left")

        self.count_badge = tk.Label(title_box, text="0 items", font=FONT_SMALL, fg=ACCENT_CYAN, bg=BG_CARD, padx=8, pady=2)
        self.count_badge.pack(side="left", padx=(10, 0))

        # Right buttons: Add Credential, Refresh
        add_btn = ModernButton(toolbar, text="+ Add Credential", bg_color=ACCENT_EMERALD, hover_color=ACCENT_EMERALD_HOVER,
                               command=self._open_add_credential_dialog)
        add_btn.pack(side="right", padx=(10, 0))

        refresh_btn = ModernButton(toolbar, text="🔄 Refresh", bg_color=BG_CARD, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY,
                                   command=self.refresh_credentials)
        refresh_btn.pack(side="right")

        # Search Bar
        search_frame = tk.Frame(parent, bg=BG_CARD, padx=12, pady=6, highlightbackground=BORDER_COLOR, highlightthickness=1)
        search_frame.pack(fill="x", padx=24, pady=(0, 14))

        search_icon = tk.Label(search_frame, text="🔍", font=FONT_BODY, fg=TEXT_MUTED, bg=BG_CARD)
        search_icon.pack(side="left", padx=(0, 8))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._filter_credentials())
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, font=FONT_BODY, bg=BG_CARD, fg=TEXT_PRIMARY,
                                insertbackground=TEXT_PRIMARY, bd=0, relief="flat")
        search_entry.pack(side="left", fill="x", expand=True)

        # Scrollable Credentials Canvas
        canvas_frame = tk.Frame(parent, bg=BG_DARK)
        canvas_frame.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        self.cred_canvas = tk.Canvas(canvas_frame, bg=BG_DARK, bd=0, highlightthickness=0)
        self.cred_scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.cred_canvas.yview, style="Vertical.TScrollbar")
        self.cred_list_inner = tk.Frame(self.cred_canvas, bg=BG_DARK)

        self.cred_list_inner.bind(
            "<Configure>",
            lambda e: self.cred_canvas.configure(scrollregion=self.cred_canvas.bbox("all"))
        )

        self.canvas_window = self.cred_canvas.create_window((0, 0), window=self.cred_list_inner, anchor="nw")
        self.cred_canvas.configure(xscrollcommand=None, yscrollcommand=self.cred_scrollbar.set)

        self.cred_canvas.pack(side="left", fill="both", expand=True)
        self.cred_scrollbar.pack(side="right", fill="y")

        self.cred_canvas.bind("<Configure>", lambda e: self.cred_canvas.itemconfig(self.canvas_window, width=e.width))

    def refresh_credentials(self):
        if not self.vault or not self.unlocked_key:
            return
        try:
            rows = self.vault.db.list_credentials()
            self.all_credentials = [dict(r) for r in rows]
            self.count_badge.configure(text=f"{len(self.all_credentials)} credentials")
            self._render_credentials(self.all_credentials)
        except Exception as exc:
            self.show_toast(f"Error loading credentials: {exc}", color=DANGER)

    def _filter_credentials(self):
        query = self.search_var.get().lower().strip()
        if not query:
            filtered = self.all_credentials
        else:
            filtered = [
                c for c in self.all_credentials
                if query in c["service"].lower() or query in c["username"].lower()
            ]
        self._render_credentials(filtered)

    def _render_credentials(self, credentials: list[dict]):
        for w in self.cred_list_inner.winfo_children():
            w.destroy()

        if not credentials:
            empty_frame = tk.Frame(self.cred_list_inner, bg=BG_DARK, pady=40)
            empty_frame.pack(fill="x")
            lbl = tk.Label(empty_frame, text="No credentials found.", font=FONT_TITLE, fg=TEXT_MUTED, bg=BG_DARK)
            lbl.pack()
            sub = tk.Label(empty_frame, text="Click '+ Add Credential' to store encrypted secrets.", font=FONT_SMALL, fg=TEXT_SECONDARY, bg=BG_DARK)
            sub.pack(pady=4)
            return

        for cred in credentials:
            service = cred["service"]
            username = cred["username"]
            updated_at = cred.get("updated_at", "")

            card = tk.Frame(self.cred_list_inner, bg=BG_CARD, padx=18, pady=14,
                            highlightbackground=BORDER_COLOR, highlightthickness=1)
            card.pack(fill="x", pady=5)

            # Left side info
            info_frame = tk.Frame(card, bg=BG_CARD)
            info_frame.pack(side="left", fill="x", expand=True)

            svc_label = tk.Label(info_frame, text=service, font=FONT_SUBTITLE, fg=TEXT_PRIMARY, bg=BG_CARD)
            svc_label.pack(anchor="w")

            user_label = tk.Label(info_frame, text=f"Username: {username}", font=FONT_BODY, fg=TEXT_SECONDARY, bg=BG_CARD)
            user_label.pack(anchor="w", pady=(2, 0))

            if updated_at:
                date_label = tk.Label(info_frame, text=f"Updated: {updated_at}", font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_CARD)
                date_label.pack(anchor="w", pady=(2, 0))

            # Right side action buttons
            btn_frame = tk.Frame(card, bg=BG_CARD)
            btn_frame.pack(side="right")

            copy_btn = ModernButton(btn_frame, text="📋 Copy", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                                    text_color=TEXT_PRIMARY, padx=10, pady=4,
                                    command=lambda s=service, u=username: self._copy_credential(s, u))
            copy_btn.pack(side="left", padx=4)

            view_btn = ModernButton(btn_frame, text="👁️ Show", bg_color=BG_CARD_HOVER, hover_color=ACCENT_BLUE,
                                    text_color=TEXT_PRIMARY, padx=10, pady=4,
                                    command=lambda s=service, u=username: self._view_credential(s, u))
            view_btn.pack(side="left", padx=4)

            del_btn = ModernButton(btn_frame, text="🗑️", bg_color=BG_CARD_HOVER, hover_color=DANGER,
                                   text_color=TEXT_SECONDARY, padx=8, pady=4,
                                   command=lambda s=service, u=username: self._delete_credential(s, u))
            del_btn.pack(side="left", padx=4)

    def _copy_credential(self, service: str, username: str):
        if not self.vault or not self.unlocked_key:
            return
        try:
            secret = self.vault.get(self.unlocked_key, service, username)
            pyperclip.copy(secret)
            self.show_toast(f"Copied password for '{service}' to clipboard!", color=SUCCESS)
        except Exception as exc:
            self.show_toast(f"Failed to decrypt password: {exc}", color=DANGER)

    def _view_credential(self, service: str, username: str):
        if not self.vault or not self.unlocked_key:
            return
        try:
            secret = self.vault.get(self.unlocked_key, service, username)
            # Show modal dialog with decrypted secret
            dlg = tk.Toplevel(self)
            dlg.title(f"Secret: {service}")
            dlg.geometry("420x240")
            dlg.configure(bg=BG_CARD)
            dlg.transient(self)
            dlg.grab_set()

            tk.Label(dlg, text=f"Service: {service}", font=FONT_TITLE, fg=ACCENT_CYAN, bg=BG_CARD).pack(anchor="w", padx=20, pady=(20, 4))
            tk.Label(dlg, text=f"Username: {username}", font=FONT_BODY, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w", padx=20, pady=(0, 14))

            secret_entry = tk.Entry(dlg, font=FONT_MONO, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
            secret_entry.insert(0, secret)
            secret_entry.configure(state="readonly")
            secret_entry.pack(fill="x", padx=20, pady=8, ipady=6)

            btn_box = tk.Frame(dlg, bg=BG_CARD)
            btn_box.pack(fill="x", padx=20, pady=(16, 0))

            ModernButton(btn_box, text="Copy Secret", bg_color=ACCENT_EMERALD, hover_color=ACCENT_EMERALD_HOVER,
                         command=lambda: [pyperclip.copy(secret), self.show_toast("Copied to clipboard!"), dlg.destroy()]).pack(side="left")
            ModernButton(btn_box, text="Close", bg_color=BG_DARK, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY,
                         command=dlg.destroy).pack(side="right")

        except Exception as exc:
            self.show_toast(f"Error: {exc}", color=DANGER)

    def _delete_credential(self, service: str, username: str):
        if messagebox.askyesno("Confirm Deletion", f"Permanently delete credential for '{service}' ({username})?"):
            try:
                self.vault.db.delete_credential(service, username)
                self.refresh_credentials()
                self.show_toast(f"Deleted '{service}' credential.", color=WARNING)
            except Exception as exc:
                self.show_toast(f"Delete failed: {exc}", color=DANGER)

    def _open_add_credential_dialog(self):
        dlg = tk.Toplevel(self)
        dlg.title("Add Credential to Vault")
        dlg.geometry("500x560")
        dlg.configure(bg=BG_CARD)
        dlg.transient(self)
        dlg.grab_set()

        header = tk.Frame(dlg, bg=BG_CARD)
        header.pack(fill="x", padx=24, pady=(20, 14))
        tk.Label(header, text="Add New Credential", font=FONT_TITLE, fg=TEXT_PRIMARY, bg=BG_CARD).pack(anchor="w")
        tk.Label(header, text="Encrypted with AES-256-GCM and unique 12-byte nonce.", font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_CARD).pack(anchor="w")

        body = tk.Frame(dlg, bg=BG_CARD)
        body.pack(fill="both", expand=True, padx=24)

        # Service
        tk.Label(body, text="Service / Website", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        svc_entry = tk.Entry(body, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                             bd=1, relief="solid", highlightthickness=1, highlightbackground=BORDER_COLOR)
        svc_entry.pack(fill="x", pady=(4, 12), ipady=5)

        # Username
        tk.Label(body, text="Username / Email", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        user_entry = tk.Entry(body, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                              bd=1, relief="solid", highlightthickness=1, highlightbackground=BORDER_COLOR)
        user_entry.pack(fill="x", pady=(4, 12), ipady=5)

        # Secret / Password
        pwd_header = tk.Frame(body, bg=BG_CARD)
        pwd_header.pack(fill="x")
        tk.Label(pwd_header, text="Secret / Password", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(side="left")

        secret_entry = tk.Entry(body, show="●", font=FONT_MONO, bg=BG_INPUT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
                                bd=1, relief="solid", highlightthickness=1, highlightbackground=BORDER_COLOR)
        secret_entry.pack(fill="x", pady=(4, 6), ipady=5)

        strength_lbl = tk.Label(body, text="Strength: Empty", font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_CARD)
        strength_lbl.pack(anchor="w", pady=(0, 12))

        def update_strength(e=None):
            lbl, col, _ = get_strength_info(secret_entry.get())
            strength_lbl.configure(text=f"Strength: {lbl}", fg=col)

        secret_entry.bind("<KeyRelease>", update_strength)

        # Generator Box
        gen_card = tk.LabelFrame(body, text=" 🎲 Built-in Password Generator ", font=FONT_SMALL, fg=ACCENT_CYAN,
                                 bg=BG_DARK, bd=1, relief="solid", highlightbackground=BORDER_COLOR)
        gen_card.pack(fill="x", pady=(0, 16), padx=2, ipady=4)

        len_box = tk.Frame(gen_card, bg=BG_DARK)
        len_box.pack(fill="x", padx=10, pady=4)
        tk.Label(len_box, text="Length:", font=FONT_SMALL, fg=TEXT_SECONDARY, bg=BG_DARK).pack(side="left")

        len_val = tk.IntVar(value=20)
        len_slider = tk.Scale(len_box, from_=8, to=64, orient="horizontal", variable=len_val, bg=BG_DARK, fg=TEXT_PRIMARY,
                              highlightthickness=0, bd=0, troughcolor=BORDER_COLOR, activebackground=ACCENT_CYAN)
        len_slider.pack(side="left", fill="x", expand=True, padx=8)

        opts_box = tk.Frame(gen_card, bg=BG_DARK)
        opts_box.pack(fill="x", padx=10, pady=2)

        chk_sym = tk.BooleanVar(value=True)
        chk_num = tk.BooleanVar(value=True)
        tk.Checkbutton(opts_box, text="Symbols (!@#)", variable=chk_sym, font=FONT_SMALL, fg=TEXT_PRIMARY,
                       bg=BG_DARK, selectcolor=BG_CARD, activebackground=BG_DARK).pack(side="left", padx=4)
        tk.Checkbutton(opts_box, text="Numbers (0-9)", variable=chk_num, font=FONT_SMALL, fg=TEXT_PRIMARY,
                       bg=BG_DARK, selectcolor=BG_CARD, activebackground=BG_DARK).pack(side="left", padx=4)

        def do_generate():
            p = generate_password(length=len_val.get(), use_symbols=chk_sym.get(), use_digits=chk_num.get())
            secret_entry.delete(0, tk.END)
            secret_entry.insert(0, p)
            update_strength()

        ModernButton(gen_card, text="Generate Strong Password", command=do_generate, bg_color=ACCENT_CYAN,
                     hover_color=ACCENT_CYAN_HOVER, font=FONT_SMALL, padx=8, pady=4).pack(pady=(4, 6))

        # Action Buttons
        btn_bar = tk.Frame(dlg, bg=BG_CARD)
        btn_bar.pack(fill="x", padx=24, pady=(0, 20))

        def save():
            svc = svc_entry.get().strip()
            usr = user_entry.get().strip()
            sec = secret_entry.get()
            if not svc or not usr or not sec:
                messagebox.showerror("Validation Error", "All fields are required.", parent=dlg)
                return
            try:
                self.vault.add(self.unlocked_key, svc, usr, sec)
                dlg.destroy()
                self.refresh_credentials()
                self.show_toast(f"Saved credential for '{svc}'", color=SUCCESS)
            except Exception as exc:
                messagebox.showerror("Error", str(exc), parent=dlg)

        ModernButton(btn_bar, text="Save Credential", bg_color=ACCENT_EMERALD, hover_color=ACCENT_EMERALD_HOVER,
                     command=save, padx=16).pack(side="left")
        ModernButton(btn_bar, text="Cancel", bg_color=BG_DARK, hover_color=BORDER_COLOR, text_color=TEXT_PRIMARY,
                     command=dlg.destroy).pack(side="right")

    # ----------------------------------------------------
    # 2. FILE ENCRYPTION VIEW
    # ----------------------------------------------------
    def _build_files_view(self, parent: tk.Frame):
        container = tk.Frame(parent, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=24, pady=20)

        title = tk.Label(container, text="Authenticated File Encryption (AES-256-GCM)", font=FONT_TITLE, fg=TEXT_PRIMARY, bg=BG_DARK)
        title.pack(anchor="w")

        sub = tk.Label(container, text="Encrypt and decrypt files with Argon2id-derived keys and tamper-evident authenticated tags.",
                       font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_DARK)
        sub.pack(anchor="w", pady=(2, 16))

        # Notebook for Encrypt / Decrypt
        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)

        encrypt_tab = tk.Frame(notebook, bg=BG_CARD, padx=24, pady=20)
        decrypt_tab = tk.Frame(notebook, bg=BG_CARD, padx=24, pady=20)
        notebook.add(encrypt_tab, text="  🔒 Encrypt File  ")
        notebook.add(decrypt_tab, text="  🔓 Decrypt File  ")

        # --- ENCRYPT TAB ---
        tk.Label(encrypt_tab, text="Select Source File to Encrypt", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        e_src_frame = tk.Frame(encrypt_tab, bg=BG_CARD)
        e_src_frame.pack(fill="x", pady=(4, 12))

        e_src_entry = tk.Entry(e_src_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        e_src_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_e_src():
            f = filedialog.askopenfilename(title="Select File to Encrypt")
            if f:
                e_src_entry.delete(0, tk.END)
                e_src_entry.insert(0, f)
                e_dst_entry.delete(0, tk.END)
                e_dst_entry.insert(0, f + ".enc")

        ModernButton(e_src_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_e_src).pack(side="right", padx=(8, 0))

        tk.Label(encrypt_tab, text="Destination Encrypted File (.enc)", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        e_dst_frame = tk.Frame(encrypt_tab, bg=BG_CARD)
        e_dst_frame.pack(fill="x", pady=(4, 12))

        e_dst_entry = tk.Entry(e_dst_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        e_dst_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_e_dst():
            f = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".enc")
            if f:
                e_dst_entry.delete(0, tk.END)
                e_dst_entry.insert(0, f)

        ModernButton(e_dst_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_e_dst).pack(side="right", padx=(8, 0))

        tk.Label(encrypt_tab, text="Passphrase", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        e_pwd_entry = tk.Entry(encrypt_tab, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        e_pwd_entry.pack(fill="x", pady=(4, 14), ipady=5)

        e_force_var = tk.BooleanVar(value=False)
        tk.Checkbutton(encrypt_tab, text="Overwrite destination file if it exists (--force)", variable=e_force_var,
                       font=FONT_SMALL, fg=TEXT_PRIMARY, bg=BG_CARD, selectcolor=BG_DARK, activebackground=BG_CARD).pack(anchor="w", pady=(0, 16))

        e_status_lbl = tk.Label(encrypt_tab, text="", font=FONT_SMALL, fg=SUCCESS, bg=BG_CARD)
        e_status_lbl.pack(anchor="w", pady=(0, 10))

        def do_encrypt_file():
            src = e_src_entry.get().strip()
            dst = e_dst_entry.get().strip()
            pwd = e_pwd_entry.get()
            if not src or not dst or not pwd:
                e_status_lbl.configure(text="Please provide source, destination, and passphrase.", fg=DANGER)
                return
            try:
                encrypt_file(Path(src), Path(dst), pwd, overwrite=e_force_var.get())
                e_status_lbl.configure(text=f"✓ Successfully encrypted to: {dst}", fg=SUCCESS)
                self.show_toast("File encrypted successfully!", color=SUCCESS)
            except Exception as exc:
                e_status_lbl.configure(text=f"Encryption error: {exc}", fg=DANGER)

        ModernButton(encrypt_tab, text="🔒 Encrypt File Now", bg_color=ACCENT_EMERALD, hover_color=ACCENT_EMERALD_HOVER,
                     command=do_encrypt_file, padx=20, pady=8).pack(anchor="w")

        # --- DECRYPT TAB ---
        tk.Label(decrypt_tab, text="Select Encrypted File (.enc)", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        d_src_frame = tk.Frame(decrypt_tab, bg=BG_CARD)
        d_src_frame.pack(fill="x", pady=(4, 12))

        d_src_entry = tk.Entry(d_src_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        d_src_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_d_src():
            f = filedialog.askopenfilename(title="Select File to Decrypt", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
            if f:
                d_src_entry.delete(0, tk.END)
                d_src_entry.insert(0, f)
                d_dst_entry.delete(0, tk.END)
                out_name = f[:-4] if f.endswith(".enc") else f + ".dec"
                d_dst_entry.insert(0, out_name)

        ModernButton(d_src_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_d_src).pack(side="right", padx=(8, 0))

        tk.Label(decrypt_tab, text="Destination Decrypted File", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        d_dst_frame = tk.Frame(decrypt_tab, bg=BG_CARD)
        d_dst_frame.pack(fill="x", pady=(4, 12))

        d_dst_entry = tk.Entry(d_dst_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        d_dst_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_d_dst():
            f = filedialog.asksaveasfilename(title="Save Decrypted File As")
            if f:
                d_dst_entry.delete(0, tk.END)
                d_dst_entry.insert(0, f)

        ModernButton(d_dst_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_d_dst).pack(side="right", padx=(8, 0))

        tk.Label(decrypt_tab, text="Passphrase", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        d_pwd_entry = tk.Entry(decrypt_tab, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        d_pwd_entry.pack(fill="x", pady=(4, 14), ipady=5)

        d_force_var = tk.BooleanVar(value=False)
        tk.Checkbutton(decrypt_tab, text="Overwrite destination file if it exists (--force)", variable=d_force_var,
                       font=FONT_SMALL, fg=TEXT_PRIMARY, bg=BG_CARD, selectcolor=BG_DARK, activebackground=BG_CARD).pack(anchor="w", pady=(0, 16))

        d_status_lbl = tk.Label(decrypt_tab, text="", font=FONT_SMALL, fg=SUCCESS, bg=BG_CARD)
        d_status_lbl.pack(anchor="w", pady=(0, 10))

        def do_decrypt_file():
            src = d_src_entry.get().strip()
            dst = d_dst_entry.get().strip()
            pwd = d_pwd_entry.get()
            if not src or not dst or not pwd:
                d_status_lbl.configure(text="Please provide source, destination, and passphrase.", fg=DANGER)
                return
            try:
                actual_dest = decrypt_file(Path(src), Path(dst) if dst else None, pwd, overwrite=d_force_var.get())
                d_status_lbl.configure(text=f"✓ Decrypted and restored as: {actual_dest.name}", fg=SUCCESS)
                self.show_toast(f"Decrypted to {actual_dest.name}!", color=SUCCESS)
            except AuthenticationError:
                d_status_lbl.configure(text="Authentication failed: incorrect passphrase or tampered file!", fg=DANGER)
            except Exception as exc:
                d_status_lbl.configure(text=f"Decryption error: {exc}", fg=DANGER)

        ModernButton(decrypt_tab, text="🔓 Decrypt File Now", bg_color=ACCENT_CYAN, hover_color=ACCENT_CYAN_HOVER,
                     command=do_decrypt_file, padx=20, pady=8).pack(anchor="w")

    # ----------------------------------------------------
    # 3. FILE INTEGRITY VIEW (HMAC)
    # ----------------------------------------------------
    def _build_integrity_view(self, parent: tk.Frame):
        container = tk.Frame(parent, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=24, pady=20)

        title = tk.Label(container, text="HMAC-SHA256 File Integrity", font=FONT_TITLE, fg=TEXT_PRIMARY, bg=BG_DARK)
        title.pack(anchor="w")

        sub = tk.Label(container, text="Create and verify tamper-proof JSON signature manifests for backups and files.",
                       font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_DARK)
        sub.pack(anchor="w", pady=(2, 16))

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)

        sign_tab = tk.Frame(notebook, bg=BG_CARD, padx=24, pady=20)
        verify_tab = tk.Frame(notebook, bg=BG_CARD, padx=24, pady=20)
        notebook.add(sign_tab, text="  🔏 Sign File (Create .sig)  ")
        notebook.add(verify_tab, text="  ✓ Verify Integrity  ")

        # --- SIGN TAB ---
        tk.Label(sign_tab, text="File to Sign", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        s_src_frame = tk.Frame(sign_tab, bg=BG_CARD)
        s_src_frame.pack(fill="x", pady=(4, 12))

        s_src_entry = tk.Entry(s_src_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        s_src_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_s_src():
            f = filedialog.askopenfilename(title="Select File to Sign")
            if f:
                s_src_entry.delete(0, tk.END)
                s_src_entry.insert(0, f)
                s_sig_entry.delete(0, tk.END)
                s_sig_entry.insert(0, f + ".sig")

        ModernButton(s_src_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_s_src).pack(side="right", padx=(8, 0))

        tk.Label(sign_tab, text="Output Signature Manifest (.sig)", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        s_sig_frame = tk.Frame(sign_tab, bg=BG_CARD)
        s_sig_frame.pack(fill="x", pady=(4, 12))

        s_sig_entry = tk.Entry(s_sig_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        s_sig_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_s_sig():
            f = filedialog.asksaveasfilename(title="Save Signature As", defaultextension=".sig")
            if f:
                s_sig_entry.delete(0, tk.END)
                s_sig_entry.insert(0, f)

        ModernButton(s_sig_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_s_sig).pack(side="right", padx=(8, 0))

        tk.Label(sign_tab, text="Secret Passphrase", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        s_pwd_entry = tk.Entry(sign_tab, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        s_pwd_entry.pack(fill="x", pady=(4, 14), ipady=5)

        s_status_lbl = tk.Label(sign_tab, text="", font=FONT_SMALL, fg=SUCCESS, bg=BG_CARD)
        s_status_lbl.pack(anchor="w", pady=(0, 10))

        def do_sign():
            src = s_src_entry.get().strip()
            sig = s_sig_entry.get().strip()
            pwd = s_pwd_entry.get()
            if not src or not sig or not pwd:
                s_status_lbl.configure(text="Please specify file, signature destination, and passphrase.", fg=DANGER)
                return
            try:
                create_signature(Path(src), Path(sig), pwd, overwrite=True)
                s_status_lbl.configure(text=f"✓ Signature created: {sig}", fg=SUCCESS)
                self.show_toast("Signature manifest created!", color=SUCCESS)
            except Exception as exc:
                s_status_lbl.configure(text=f"Signing error: {exc}", fg=DANGER)

        ModernButton(sign_tab, text="🔏 Generate Signature", bg_color=ACCENT_EMERALD, hover_color=ACCENT_EMERALD_HOVER,
                     command=do_sign, padx=20, pady=8).pack(anchor="w")

        # --- VERIFY TAB ---
        tk.Label(verify_tab, text="Source File to Check", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        v_src_frame = tk.Frame(verify_tab, bg=BG_CARD)
        v_src_frame.pack(fill="x", pady=(4, 12))

        v_src_entry = tk.Entry(v_src_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        v_src_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_v_src():
            f = filedialog.askopenfilename(title="Select File to Verify")
            if f:
                v_src_entry.delete(0, tk.END)
                v_src_entry.insert(0, f)
                if os.path.exists(f + ".sig"):
                    v_sig_entry.delete(0, tk.END)
                    v_sig_entry.insert(0, f + ".sig")

        ModernButton(v_src_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_v_src).pack(side="right", padx=(8, 0))

        tk.Label(verify_tab, text="Signature File (.sig)", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        v_sig_frame = tk.Frame(verify_tab, bg=BG_CARD)
        v_sig_frame.pack(fill="x", pady=(4, 12))

        v_sig_entry = tk.Entry(v_sig_frame, font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        v_sig_entry.pack(side="left", fill="x", expand=True, ipady=5)

        def browse_v_sig():
            f = filedialog.askopenfilename(title="Select Signature File", filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")])
            if f:
                v_sig_entry.delete(0, tk.END)
                v_sig_entry.insert(0, f)

        ModernButton(v_sig_frame, text="Browse...", bg_color=BG_CARD_HOVER, hover_color=ACCENT_CYAN,
                     text_color=TEXT_PRIMARY, command=browse_v_sig).pack(side="right", padx=(8, 0))

        tk.Label(verify_tab, text="Passphrase", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        v_pwd_entry = tk.Entry(verify_tab, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        v_pwd_entry.pack(fill="x", pady=(4, 14), ipady=5)

        v_result_card = tk.Frame(verify_tab, bg=BG_DARK, padx=16, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        v_result_card.pack(fill="x", pady=(0, 16))

        v_res_lbl = tk.Label(v_result_card, text="Ready to verify. Select file and signature.", font=FONT_BOLD, fg=TEXT_MUTED, bg=BG_DARK)
        v_res_lbl.pack(anchor="w")

        def do_verify():
            src = v_src_entry.get().strip()
            sig = v_sig_entry.get().strip()
            pwd = v_pwd_entry.get()
            if not src or not sig or not pwd:
                v_res_lbl.configure(text="Please select file, signature, and passphrase.", fg=DANGER)
                return
            try:
                valid = verify_signature(Path(src), Path(sig), pwd)
                if valid:
                    v_res_lbl.configure(text="🛡️ INTEGRITY VERIFIED: HMAC match! File is authentic and untampered.", fg=SUCCESS)
                    self.show_toast("Integrity Verified!", color=SUCCESS)
                else:
                    v_res_lbl.configure(text="⚠️ VERIFICATION FAILED: Signature mismatch or invalid passphrase!", fg=DANGER)
                    self.show_toast("Integrity check failed!", color=DANGER)
            except Exception as exc:
                v_res_lbl.configure(text=f"Verification error: {exc}", fg=DANGER)

        ModernButton(verify_tab, text="✓ Verify Integrity", bg_color=ACCENT_CYAN, hover_color=ACCENT_CYAN_HOVER,
                     command=do_verify, padx=20, pady=8).pack(anchor="w")

    # ----------------------------------------------------
    # 4. SETTINGS & SECURITY VIEW
    # ----------------------------------------------------
    def _build_settings_view(self, parent: tk.Frame):
        container = tk.Frame(parent, bg=BG_DARK)
        container.pack(fill="both", expand=True, padx=24, pady=20)

        title = tk.Label(container, text="Security & Vault Settings", font=FONT_TITLE, fg=TEXT_PRIMARY, bg=BG_DARK)
        title.pack(anchor="w")

        sub = tk.Label(container, text="Review cryptographic architecture and rotate master password.",
                       font=FONT_SMALL, fg=TEXT_MUTED, bg=BG_DARK)
        sub.pack(anchor="w", pady=(2, 16))

        # Change Master Password Card
        pwd_card = tk.LabelFrame(container, text=" 🔄 Change Master Password ", font=FONT_SUBTITLE, fg=ACCENT_CYAN,
                                 bg=BG_CARD, bd=1, relief="solid", highlightbackground=BORDER_COLOR, padx=18, pady=16)
        pwd_card.pack(fill="x", pady=(0, 16))

        tk.Label(pwd_card, text="Current Master Password", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        curr_pwd = tk.Entry(pwd_card, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        curr_pwd.pack(fill="x", pady=(4, 10), ipady=4)

        tk.Label(pwd_card, text="New Master Password", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        new_pwd = tk.Entry(pwd_card, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        new_pwd.pack(fill="x", pady=(4, 10), ipady=4)

        tk.Label(pwd_card, text="Confirm New Master Password", font=FONT_BOLD, fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w")
        conf_pwd = tk.Entry(pwd_card, show="●", font=FONT_BODY, bg=BG_INPUT, fg=TEXT_PRIMARY, bd=1, relief="solid")
        conf_pwd.pack(fill="x", pady=(4, 12), ipady=4)

        chg_status_lbl = tk.Label(pwd_card, text="", font=FONT_SMALL, fg=SUCCESS, bg=BG_CARD)
        chg_status_lbl.pack(anchor="w", pady=(0, 8))

        def do_change_pwd():
            c = curr_pwd.get()
            n = new_pwd.get()
            cf = conf_pwd.get()
            if not c or not n:
                chg_status_lbl.configure(text="Please fill in all password fields.", fg=DANGER)
                return
            if n != cf:
                chg_status_lbl.configure(text="New passwords do not match.", fg=DANGER)
                return
            try:
                self.vault.change_master_password(c, n)
                # Re-derive unlocked key
                self.unlocked_key = self.vault.unlock(n)
                curr_pwd.delete(0, tk.END)
                new_pwd.delete(0, tk.END)
                conf_pwd.delete(0, tk.END)
                chg_status_lbl.configure(text="✓ Master password changed & credentials re-encrypted!", fg=SUCCESS)
                self.show_toast("Master password changed!", color=SUCCESS)
            except AuthenticationError:
                chg_status_lbl.configure(text="Current password incorrect.", fg=DANGER)
            except Exception as exc:
                chg_status_lbl.configure(text=f"Error: {exc}", fg=DANGER)

        ModernButton(pwd_card, text="Re-encrypt Vault with New Password", bg_color=ACCENT_EMERALD,
                     hover_color=ACCENT_EMERALD_HOVER, command=do_change_pwd).pack(anchor="w")

        # Database & Specs Info Card
        specs_card = tk.LabelFrame(container, text=" 🛡️ Security Architecture Specs ", font=FONT_SUBTITLE, fg=ACCENT_CYAN,
                                   bg=BG_CARD, bd=1, relief="solid", highlightbackground=BORDER_COLOR, padx=18, pady=16)
        specs_card.pack(fill="x")

        self.db_path_lbl = tk.Label(specs_card, text=f"Database: {self.db_path.resolve()}", font=FONT_MONO, fg=TEXT_SECONDARY, bg=BG_CARD)
        self.db_path_lbl.pack(anchor="w", pady=(0, 6))

        specs = [
            ("Key Derivation (KDF)", "Argon2id (Memory: 64 MiB, Time: 3 iterations, Parallelism: 4 threads)"),
            ("Cipher", "AES-256-GCM (Authenticated 256-bit encryption with 12-byte random nonces)"),
            ("Metadata Binding", "Length-prefixed Authenticated Associated Data (AAD v2) prevents field splicing"),
            ("Integrity Verification", "Streaming 64 KiB HMAC-SHA256 with constant-time comparison"),
            ("Database Engine", "SQLite WAL (Write-Ahead Logging) mode with parameterized atomic transactions"),
        ]

        for title_str, val_str in specs:
            row = tk.Frame(specs_card, bg=BG_CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"• {title_str}: ", font=FONT_BOLD, fg=TEXT_PRIMARY, bg=BG_CARD).pack(side="left")
            tk.Label(row, text=val_str, font=FONT_SMALL, fg=TEXT_SECONDARY, bg=BG_CARD).pack(side="left")

    def _update_settings_display(self):
        if hasattr(self, "db_path_lbl"):
            self.db_path_lbl.configure(text=f"Database: {self.db_path.resolve()}")


def run_app(db_path: Path | None = None):
    app = CryptoVaultGUI(db_path=db_path)
    app.mainloop()


if __name__ == "__main__":
    run_app()
