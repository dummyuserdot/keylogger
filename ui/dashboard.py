"""
KeySentinel — Desktop Security Dashboard (Tkinter)
Professional cybersecurity monitoring console for Windows 10 & 11.
Features dark theme, real-time telemetry, threat reviewing, audit logs,
and authenticated shutdown workflow.
"""

import sys
import threading
import time
from typing import Optional

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

from config import APP_DISPLAY_NAME, APP_VERSION
from detection.engine import detection_engine
from detection.rules import DetectedThreat, ThreatSeverity
from logging_config import (
    CATEGORY_LIFECYCLE,
    get_recent_security_events,
    log_security_event,
)
from monitoring.worker import MonitoringState, monitor_worker
from security.auth import auth_manager
from security.protection import protector
from ui.auth_dialog import AuthDialog


class KeySentinelDashboard:
    """
    Tkinter desktop application dashboard.
    """

    def __init__(self, root: Optional[tk.Tk] = None):
        if not TKINTER_AVAILABLE:
            raise RuntimeError("Tkinter is not installed in this environment.")

        self.root = root if root else tk.Tk()
        self.root.title(f"{APP_DISPLAY_NAME} v{APP_VERSION}")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)
        self.root.configure(bg="#0b1120")

        # Color palette
        self.c_bg = "#0b1120"
        self.c_card = "#1e293b"
        self.c_border = "#334155"
        self.c_text = "#f8fafc"
        self.c_muted = "#94a3b8"
        self.c_primary = "#38bdf8"
        self.c_danger = "#ef4444"
        self.c_success = "#10b981"
        self.c_warning = "#f59e0b"

        # Intercept window close to enforce admin password
        self.root.protocol("WM_DELETE_WINDOW", self.on_request_close)

        # Build UI layout
        self._setup_styles()
        self._build_header()
        self._build_stats_ribbon()
        self._build_main_notebook()
        self._build_status_bar()

        # Connect background state listeners
        monitor_worker.add_state_listener(self._on_monitor_state_change)
        detection_engine.add_threat_listener(self._on_threat_detected)

        # Start initial monitoring
        monitor_worker.start_monitoring()

        # Start periodic UI refresh ticker
        self.root.after(1500, self._periodic_ui_refresh)

    def _setup_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#0f172a",
            foreground="#f8fafc",
            fieldbackground="#0f172a",
            rowheight=26,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#1e293b",
            foreground="#38bdf8",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map("Treeview", background=[("selected", "#0284c7")], foreground=[("selected", "#ffffff")])

        style.configure("TNotebook", background="#0b1120", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e293b", foreground="#94a3b8", padding=[16, 8], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#38bdf8")], foreground=[("selected", "#0f172a")])

    def _build_header(self):
        header = tk.Frame(self.root, bg=self.c_card, height=64, padx=20, pady=12)
        header.pack(fill=tk.X, side=tk.TOP)

        # Brand / Title
        brand_frame = tk.Frame(header, bg=self.c_card)
        brand_frame.pack(side=tk.LEFT)

        icon_lbl = tk.Label(brand_frame, text="🛡️", font=("Segoe UI", 18), bg=self.c_card)
        icon_lbl.pack(side=tk.LEFT, padx=(0, 10))

        title_subframe = tk.Frame(brand_frame, bg=self.c_card)
        title_subframe.pack(side=tk.LEFT)

        app_lbl = tk.Label(
            title_subframe,
            text="KeySentinel",
            font=("Segoe UI", 14, "bold"),
            fg=self.c_text,
            bg=self.c_card,
        )
        app_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            title_subframe,
            text="Windows Keylogger Detection & Security Monitor",
            font=("Segoe UI", 8),
            fg=self.c_muted,
            bg=self.c_card,
        )
        sub_lbl.pack(anchor="w")

        # Action Buttons on Right
        btn_box = tk.Frame(header, bg=self.c_card)
        btn_box.pack(side=tk.RIGHT)

        self.btn_toggle_mon = tk.Button(
            btn_box,
            text="⏸ Pause Monitor",
            command=self.toggle_monitoring,
            bg="#334155",
            fg=self.c_text,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self.btn_toggle_mon.pack(side=tk.LEFT, padx=6)

        self.btn_scan = tk.Button(
            btn_box,
            text="🔍 Scan Now",
            command=self.trigger_manual_scan,
            bg="#0284c7",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self.btn_scan.pack(side=tk.LEFT, padx=6)

        self.btn_shutdown = tk.Button(
            btn_box,
            text="🛑 Exit (Auth Required)",
            command=self.on_request_close,
            bg="#dc2626",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self.btn_shutdown.pack(side=tk.LEFT, padx=6)

    def _build_stats_ribbon(self):
        ribbon = tk.Frame(self.root, bg=self.c_bg, padx=20, pady=12)
        ribbon.pack(fill=tk.X)

        # 4 Stat Cards
        self.card_status = self._create_stat_card(ribbon, "MONITOR STATUS", "ACTIVE", self.c_success)
        self.card_status.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.card_threats = self._create_stat_card(ribbon, "DETECTED THREATS", "0", self.c_primary)
        self.card_threats.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        self.card_integrity = self._create_stat_card(ribbon, "CONFIG INTEGRITY", "VERIFIED", self.c_success)
        self.card_integrity.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        priv_status = "ELEVATED ADMIN" if protector.is_running_as_admin() else "STANDARD USER"
        priv_color = self.c_success if protector.is_running_as_admin() else self.c_warning
        self.card_priv = self._create_stat_card(ribbon, "PRIVILEGE LEVEL", priv_status, priv_color)
        self.card_priv.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))

    def _create_stat_card(self, parent, label_text, initial_val, color):
        frame = tk.Frame(parent, bg=self.c_card, padx=14, pady=10, relief=tk.FLAT)
        lbl = tk.Label(frame, text=label_text, font=("Segoe UI", 8, "bold"), fg=self.c_muted, bg=self.c_card)
        lbl.pack(anchor="w")
        val_lbl = tk.Label(frame, text=initial_val, font=("Segoe UI", 12, "bold"), fg=color, bg=self.c_card)
        val_lbl.pack(anchor="w", pady=(2, 0))
        frame.val_label = val_lbl  # store reference for update
        return frame

    def _build_main_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 10))

        # Tab 1: Suspicious Processes & Threat Monitor
        tab_threats = tk.Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(tab_threats, text="⚠️ Suspicious Processes")
        self._build_threats_tab(tab_threats)

        # Tab 2: Security Event Log
        tab_logs = tk.Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(tab_logs, text="📜 Security Audit Log")
        self._build_logs_tab(tab_logs)

        # Tab 3: Persistence & Startup
        tab_persist = tk.Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(tab_persist, text="🔄 Startup & Persistence")
        self._build_persist_tab(tab_persist)

        # Tab 4: Configuration & Whitelist
        tab_settings = tk.Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(tab_settings, text="⚙️ Detection Settings")
        self._build_settings_tab(tab_settings)

    def _build_threats_tab(self, parent):
        # Action Toolbar above table
        toolbar = tk.Frame(parent, bg=self.c_bg, pady=6)
        toolbar.pack(fill=tk.X)

        tk.Label(
            toolbar,
            text="Active Threat Detections & Keyboard Hook Alerts",
            font=("Segoe UI", 10, "bold"),
            fg=self.c_text,
            bg=self.c_bg,
        ).pack(side=tk.LEFT)

        btn_inspect = tk.Button(
            toolbar,
            text="Inspect Details",
            command=self._inspect_selected_threat,
            bg="#334155",
            fg=self.c_text,
            relief=tk.FLAT,
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn_inspect.pack(side=tk.RIGHT, padx=4)

        btn_whitelist = tk.Button(
            toolbar,
            text="Whitelist Process",
            command=self._whitelist_selected_threat,
            bg="#334155",
            fg=self.c_text,
            relief=tk.FLAT,
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn_whitelist.pack(side=tk.RIGHT, padx=4)

        btn_quarantine = tk.Button(
            toolbar,
            text="Terminate / Neutralize",
            command=self._quarantine_selected_threat,
            bg=self.c_danger,
            fg="#ffffff",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            cursor="hand2",
        )
        btn_quarantine.pack(side=tk.RIGHT, padx=4)

        # Treeview Table
        cols = ("pid", "name", "severity", "confidence", "verdict", "path")
        self.threat_tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        self.threat_tree.heading("pid", text="PID")
        self.threat_tree.heading("name", text="Process Name")
        self.threat_tree.heading("severity", text="Severity")
        self.threat_tree.heading("confidence", text="Confidence")
        self.threat_tree.heading("verdict", text="Verdict")
        self.threat_tree.heading("path", text="Executable Path")

        self.threat_tree.column("pid", width=70, anchor="center")
        self.threat_tree.column("name", width=160)
        self.threat_tree.column("severity", width=90, anchor="center")
        self.threat_tree.column("confidence", width=90, anchor="center")
        self.threat_tree.column("verdict", width=190)
        self.threat_tree.column("path", width=380)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=scrollbar.set)

        self.threat_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_logs_tab(self, parent):
        top_bar = tk.Frame(parent, bg=self.c_bg, pady=6)
        top_bar.pack(fill=tk.X)

        tk.Label(
            top_bar,
            text="Tamper-Evident Security Audit Trail (Passwords & Keystrokes are strictly excluded)",
            font=("Segoe UI", 9),
            fg=self.c_muted,
            bg=self.c_bg,
        ).pack(side=tk.LEFT)

        btn_refresh_logs = tk.Button(
            top_bar,
            text="Refresh Logs",
            command=self._refresh_logs_ui,
            bg="#334155",
            fg=self.c_text,
            relief=tk.FLAT,
            padx=10,
            pady=3,
        )
        btn_refresh_logs.pack(side=tk.RIGHT)

        cols = ("time", "category", "severity", "action", "status")
        self.log_tree = ttk.Treeview(parent, columns=cols, show="headings")
        self.log_tree.heading("time", text="Timestamp")
        self.log_tree.heading("category", text="Category")
        self.log_tree.heading("severity", text="Severity")
        self.log_tree.heading("action", text="Action / Event")
        self.log_tree.heading("status", text="Result")

        self.log_tree.column("time", width=180)
        self.log_tree.column("category", width=150)
        self.log_tree.column("severity", width=90, anchor="center")
        self.log_tree.column("action", width=250)
        self.log_tree.column("status", width=90, anchor="center")

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=scrollbar.set)

        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_persist_tab(self, parent):
        cols = ("name", "location", "command")
        self.persist_tree = ttk.Treeview(parent, columns=cols, show="headings")
        self.persist_tree.heading("name", text="Program / Key Name")
        self.persist_tree.heading("location", text="Registry Key / Folder")
        self.persist_tree.heading("command", text="Command Path")

        self.persist_tree.column("name", width=200)
        self.persist_tree.column("location", width=280)
        self.persist_tree.column("command", width=420)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.persist_tree.yview)
        self.persist_tree.configure(yscrollcommand=scrollbar.set)

        self.persist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_settings_tab(self, parent):
        frame = tk.Frame(parent, bg=self.c_card, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(
            frame,
            text="Defensive Monitoring Settings",
            font=("Segoe UI", 12, "bold"),
            fg=self.c_text,
            bg=self.c_card,
        ).pack(anchor="w", pady=(0, 10))

        tk.Label(
            frame,
            text="• WH_KEYBOARD_LL Low-Level Keyboard Hook Detection: ENABLED\n"
            "• Raw Input (RIDEV_INPUTSINK) Background Sniffing Detection: ENABLED\n"
            "• GetAsyncKeyState Polling Loop Heuristics: ENABLED\n"
            "• Windows Startup Run / RunOnce Registry Auditing: ENABLED\n"
            "• Configuration File Integrity Baseline Hash: ACTIVE\n"
            "• Prototype Admin Credential Hash Verification: ENABLED (Pass: 27254)",
            font=("Segoe UI", 10),
            fg=self.c_muted,
            bg=self.c_card,
            justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 16))

        tk.Label(
            frame,
            text="Known Legitimate Whitelisted Software (Anti-False-Positive):",
            font=("Segoe UI", 10, "bold"),
            fg=self.c_primary,
            bg=self.c_card,
        ).pack(anchor="w", pady=(0, 6))

        tk.Label(
            frame,
            text="Discord Overlay (discord.exe), Microsoft PowerToys Keyboard Remapper, "
            "OBS Studio Hotkeys (obs64.exe), NVIDIA GeForce Overlay (nvcontainer.exe), "
            "ShareX Screen Capture.",
            font=("Segoe UI", 9),
            fg=self.c_muted,
            bg=self.c_card,
            wraplength=600,
            justify=tk.LEFT,
        ).pack(anchor="w")

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=self.c_card, height=26, padx=12, pady=4)
        bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_msg = tk.Label(
            bar,
            text="KeySentinel engine initialized. Monitoring keyboard-capture hooks in background.",
            font=("Segoe UI", 8),
            fg=self.c_muted,
            bg=self.c_card,
        )
        self.status_msg.pack(side=tk.LEFT)

        ver_lbl = tk.Label(
            bar,
            text=f"v{APP_VERSION} | Defending Windows Keystroke Subsystem",
            font=("Segoe UI", 8),
            fg=self.c_primary,
            bg=self.c_card,
        )
        ver_lbl.pack(side=tk.RIGHT)

    def toggle_monitoring(self):
        if monitor_worker.is_running():
            monitor_worker.stop_monitoring()
            self.btn_toggle_mon.configure(text="▶ Start Monitor", bg=self.c_success)
            self.card_status.val_label.configure(text="PAUSED", fg=self.c_warning)
            self.status_msg.configure(text="Monitoring paused by operator.")
        else:
            monitor_worker.start_monitoring()
            self.btn_toggle_mon.configure(text="⏸ Pause Monitor", bg="#334155")
            self.card_status.val_label.configure(text="ACTIVE", fg=self.c_success)
            self.status_msg.configure(text="Monitoring resumed.")

    def trigger_manual_scan(self):
        self.status_msg.configure(text="Running full security inspection scan...")
        self.root.update_idletasks()
        threats = detection_engine.scan_now()
        self._refresh_threats_ui()
        self._refresh_logs_ui()
        self.status_msg.configure(text=f"Scan complete. {len(threats)} total threat(s) flagged.")

    def _on_threat_detected(self, threat: DetectedThreat):
        # Update UI thread-safely via root.after
        self.root.after(0, self._refresh_threats_ui)

    def _on_monitor_state_change(self, state: MonitoringState):
        def _update():
            if state == MonitoringState.RUNNING:
                self.card_status.val_label.configure(text="ACTIVE", fg=self.c_success)
            else:
                self.card_status.val_label.configure(text="STOPPED", fg=self.c_danger)
        self.root.after(0, _update)

    def _refresh_threats_ui(self):
        threats = detection_engine.get_all_detected_threats()
        self.card_threats.val_label.configure(text=str(len(threats)), fg=self.c_danger if threats else self.c_primary)

        # Clear existing rows
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)

        for t in threats:
            self.threat_tree.insert(
                "",
                tk.END,
                iid=t.threat_id,
                values=(
                    t.pid if t.pid > 0 else "N/A",
                    t.process_name,
                    t.severity.value,
                    f"{t.confidence_score}%",
                    t.verdict,
                    t.executable_path,
                ),
            )

    def _refresh_logs_ui(self):
        events = get_recent_security_events(60)
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)

        for ev in reversed(events):
            t_str = ev.get("timestamp", "").split("T")[-1][:8]
            self.log_tree.insert(
                "",
                tk.END,
                values=(
                    t_str,
                    ev.get("category"),
                    ev.get("severity"),
                    ev.get("action"),
                    "SUCCESS" if ev.get("success") else "FAILED",
                ),
            )

    def _periodic_ui_refresh(self):
        self._refresh_threats_ui()
        self._refresh_logs_ui()
        # Schedule next refresh
        self.root.after(3000, self._periodic_ui_refresh)

    def _inspect_selected_threat(self):
        selected = self.threat_tree.selection()
        if not selected:
            messagebox.showinfo("Selection Required", "Please select a threat from the table to inspect.", parent=self.root)
            return

        threat_id = selected[0]
        threats = {t.threat_id: t for t in detection_engine.get_all_detected_threats()}
        threat = threats.get(threat_id)
        if not threat:
            return

        # Show details window
        details_win = tk.Toplevel(self.root)
        details_win.title(f"Threat Evidence — {threat.process_name}")
        details_win.geometry("560x420")
        details_win.configure(bg="#0f172a")

        body = tk.Frame(details_win, bg="#0f172a", padx=20, pady=20)
        body.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            body,
            text=f"Process: {threat.process_name} (PID: {threat.pid})",
            font=("Segoe UI", 12, "bold"),
            fg="#38bdf8",
            bg="#0f172a",
        ).pack(anchor="w")

        tk.Label(
            body,
            text=f"Verdict: {threat.verdict} | Confidence: {threat.confidence_score}%",
            font=("Segoe UI", 10, "bold"),
            fg="#ef4444" if threat.is_confirmed else "#f59e0b",
            bg="#0f172a",
        ).pack(anchor="w", pady=(2, 10))

        tk.Label(
            body,
            text=f"Path: {threat.executable_path}\nDetected: {threat.detected_at}",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0f172a",
            justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 10))

        tk.Label(
            body,
            text="Supporting Evidence & Observed Indicators:",
            font=("Segoe UI", 10, "bold"),
            fg="#f8fafc",
            bg="#0f172a",
        ).pack(anchor="w", pady=(0, 6))

        for ind in threat.indicators:
            tk.Label(
                body,
                text=f"• [{ind.severity.value}] {ind.title}\n  {ind.description}",
                font=("Segoe UI", 9),
                fg="#cbd5e1",
                bg="#0f172a",
                justify=tk.LEFT,
                wraplength=500,
            ).pack(anchor="w", pady=2)

    def _whitelist_selected_threat(self):
        selected = self.threat_tree.selection()
        if not selected:
            return
        threat_id = selected[0]
        threats = {t.threat_id: t for t in detection_engine.get_all_detected_threats()}
        threat = threats.get(threat_id)
        if threat:
            detection_engine.whitelist_process(threat.pid, threat.process_name)
            self._refresh_threats_ui()
            messagebox.showinfo("Whitelisted", f"{threat.process_name} has been added to authorized whitelist.", parent=self.root)

    def _quarantine_selected_threat(self):
        selected = self.threat_tree.selection()
        if not selected:
            return
        threat_id = selected[0]
        threats = {t.threat_id: t for t in detection_engine.get_all_detected_threats()}
        threat = threats.get(threat_id)
        if not threat:
            return

        if messagebox.askyesno(
            "Confirm Neutralization",
            f"Are you sure you want to terminate/quarantine {threat.process_name} (PID {threat.pid})?",
            parent=self.root,
        ):
            ok, msg = detection_engine.quarantine_process(threat_id)
            if ok:
                messagebox.showinfo("Success", msg, parent=self.root)
            else:
                messagebox.showerror("Error", msg, parent=self.root)
            self._refresh_threats_ui()

    def on_request_close(self):
        """
        Intercepts window close or Exit button.
        CRITICAL REQUIREMENT: Requires Administrator password '27254'
        before terminating KeySentinel!
        """
        AuthDialog(
            parent=self.root,
            on_success=self._perform_graceful_shutdown,
            title="Administrator Authorization Required to Exit",
        )

    def _perform_graceful_shutdown(self):
        """
        Authorized graceful shutdown sequence.
        """
        log_security_event(
            category=CATEGORY_LIFECYCLE,
            action="APPLICATION_SHUTDOWN_AUTHORIZED",
            severity="INFO",
            details={"authorized": True},
            success=True,
        )
        monitor_worker.stop_monitoring()
        self.root.destroy()
        sys.exit(0)
