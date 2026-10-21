"""
KeySentinel — Administrator Authentication Dialog (Tkinter)
Provides a secure password authentication modal to protect the monitoring
engine from unauthorized termination.
Prototype password: '27254'
"""

import sys
import threading
from typing import Callable, Optional

# Tkinter imports with fallback guard
try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

from logging_config import (
    CATEGORY_AUTH,
    log_security_event,
)
from security.auth import auth_manager


class AuthDialog:
    """
    Modal authentication dialog with masked password input,
    attempt throttling, debouncing, and graceful shutdown authorization.
    """

    def __init__(
        self,
        parent: Optional[tk.Misc] = None,
        on_success: Optional[Callable[[], None]] = None,
        title: str = "KeySentinel — Administrator Authentication",
    ):
        if not TKINTER_AVAILABLE:
            raise RuntimeError("Tkinter is not available in this Python environment.")

        self.parent = parent
        self.on_success = on_success
        self.authorized = False
        self._is_verifying = False

        self.dialog = tk.Toplevel(parent) if parent else tk.Tk()
        self.dialog.title(title)
        self.dialog.geometry("450x300")
        self.dialog.resizable(False, False)
        self.dialog.configure(bg="#0f172a")

        # Keep on top and make modal
        self.dialog.transient(parent) if parent else None
        self.dialog.grab_set()

        self._build_ui()
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_cancel)

    def _build_ui(self):
        # Header banner
        header = tk.Frame(self.dialog, bg="#1e293b", height=50)
        header.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(
            header,
            text="🛡️ Administrator Authorization Required",
            font=("Segoe UI", 12, "bold"),
            fg="#38bdf8",
            bg="#1e293b",
            padx=16,
            pady=12,
        )
        title_lbl.pack(anchor="w")

        # Body Frame
        body = tk.Frame(self.dialog, bg="#0f172a", padx=24, pady=16)
        body.pack(fill=tk.BOTH, expand=True)

        desc = tk.Label(
            body,
            text=(
                "Terminating KeySentinel or changing protection settings requires "
                "the administrator credential. Security monitoring remains active "
                "until verified."
            ),
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0f172a",
            wraplength=400,
            justify=tk.LEFT,
        )
        desc.pack(anchor="w", pady=(0, 16))

        # Password input label
        pwd_lbl = tk.Label(
            body,
            text="Administrator Password:",
            font=("Segoe UI", 10, "bold"),
            fg="#f1f5f9",
            bg="#0f172a",
        )
        pwd_lbl.pack(anchor="w", pady=(0, 4))

        # Password entry field (masked)
        self.pwd_entry = tk.Entry(
            body,
            show="•",
            font=("Segoe UI", 12),
            bg="#1e293b",
            fg="#ffffff",
            insertbackground="#38bdf8",
            relief=tk.FLAT,
            highlightthickness=1,
            highlightcolor="#38bdf8",
            highlightbackground="#334155",
        )
        self.pwd_entry.pack(fill=tk.X, ipady=6, pady=(0, 8))
        self.pwd_entry.focus_set()
        self.pwd_entry.bind("<Return>", lambda e: self.on_verify())

        # Status / Error message label
        self.status_lbl = tk.Label(
            body,
            text="",
            font=("Segoe UI", 9),
            fg="#ef4444",
            bg="#0f172a",
            wraplength=400,
            justify=tk.LEFT,
        )
        self.status_lbl.pack(anchor="w", pady=(0, 12))

        # Buttons Frame
        btn_frame = tk.Frame(body, bg="#0f172a")
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        # Cancel Button
        self.btn_cancel = tk.Button(
            btn_frame,
            text="Cancel",
            command=self.on_cancel,
            bg="#334155",
            fg="#f8fafc",
            activebackground="#475569",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=6,
            cursor="hand2",
        )
        self.btn_cancel.pack(side=tk.RIGHT, padx=(8, 0))

        # Verify & Proceed Button (debounced)
        self.btn_verify = tk.Button(
            btn_frame,
            text="Verify & Shutdown",
            command=self.on_verify,
            bg="#dc2626",
            fg="#ffffff",
            activebackground="#b91c1c",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=6,
            cursor="hand2",
        )
        self.btn_verify.pack(side=tk.RIGHT)

    def on_verify(self):
        """
        Handles verify click. Debounced to prevent duplicate invocations.
        """
        if self._is_verifying:
            return  # Prevent multiple rapid clicks

        self._is_verifying = True
        self.btn_verify.configure(state=tk.DISABLED, text="Verifying...")
        self.status_lbl.configure(text="")

        entered_pwd = self.pwd_entry.get()

        # Check password with authentication manager
        is_valid, msg = auth_manager.verify_password(entered_pwd, source_context="UI_AUTH_MODAL")

        if is_valid:
            self.authorized = True
            self.status_lbl.configure(text="Authentication successful! Shutting down...", fg="#10b981")
            self.dialog.after(600, self._complete_shutdown)
        else:
            self.status_lbl.configure(text=msg, fg="#ef4444")
            self.pwd_entry.delete(0, tk.END)
            self._is_verifying = False
            self.btn_verify.configure(state=tk.NORMAL, text="Verify & Shutdown")

    def _complete_shutdown(self):
        self.dialog.destroy()
        if self.on_success:
            self.on_success()

    def on_cancel(self):
        """Cancels authorization. Monitoring stays completely active."""
        log_security_event(
            category=CATEGORY_AUTH,
            action="AUTH_DIALOG_CANCELLED",
            severity="INFO",
            details={"status": "MONITORING_REMAINS_ACTIVE"},
            success=True,
        )
        self.authorized = False
        self.dialog.destroy()
