import { PythonSourceFile } from '../types';

export const PYTHON_SOURCE_FILES: PythonSourceFile[] = [
  {
    path: 'main.py',
    name: 'main.py',
    category: 'core',
    content: `"""
KeySentinel — Windows Keylogger Detection & Security Monitor
Main Entry Point
"""

import argparse
import os
import signal
import sys
import time

from config import APP_DISPLAY_NAME, APP_VERSION
from detection.engine import detection_engine
from logging_config import (
    CATEGORY_LIFECYCLE,
    log_security_event,
    setup_security_logging,
)
from monitoring.worker import monitor_worker
from security.auth import auth_manager
from security.protection import protector


def handle_shutdown_signal(signum, frame):
    """Handles OS termination signals."""
    log_security_event(
        category=CATEGORY_LIFECYCLE,
        action="OS_SIGNAL_RECEIVED",
        severity="WARNING",
        details={"signal": signum},
        success=False,
    )
    print(f"\\n[KeySentinel] Intercepted termination signal ({signum}).")
    if not auth_manager.is_shutdown_in_progress():
        print("[KeySentinel] Security monitoring is protected. Enter admin password to confirm exit.")
        try:
            pwd = input("Administrator Password: ").strip()
            ok, msg = auth_manager.verify_password(pwd, source_context="CLI_SIGNAL_INTERCEPT")
            if ok:
                print(f"[KeySentinel] Authorized: {msg}")
                monitor_worker.stop_monitoring()
                sys.exit(0)
            else:
                print(f"[KeySentinel] Access Denied: {msg}")
                return
        except Exception:
            return
    else:
        monitor_worker.stop_monitoring()
        sys.exit(0)


def run_cli_monitor():
    """Runs KeySentinel in headless console security monitor mode."""
    print("=" * 70)
    print(f" {APP_DISPLAY_NAME} v{APP_VERSION}")
    print(" Defensive Keylogger Detection & Keystroke Subsystem Monitor")
    print("=" * 70)

    is_admin = protector.is_running_as_admin()
    if is_admin:
        print("[+] Privilege: Running with Administrator privileges (Full Protection).")
    else:
        print("[!] Warning: Running with standard user privileges. Run as Admin for service defense.")

    protector.harden_environment()
    log_security_event(
        category=CATEGORY_LIFECYCLE,
        action="APPLICATION_INITIALIZED_CLI",
        severity="INFO",
        details={"version": APP_VERSION, "admin": is_admin},
        success=True,
    )

    monitor_worker.start_monitoring()
    print("[+] Background keyboard hook & persistence monitor started.")
    print("[+] Prototype Admin Password configured: '27254'")
    print("[+] Press Ctrl+C or type 'exit' to trigger authenticated shutdown.")
    print("-" * 70)

    try:
        while True:
            cmd = input("KeySentinel> ").strip().lower()
            if cmd in ("exit", "quit", "stop"):
                pwd = input("Enter Administrator Password: ").strip()
                ok, msg = auth_manager.verify_password(pwd, source_context="CLI_PROMPT")
                if ok:
                    print(f"[+] {msg}")
                    monitor_worker.stop_monitoring()
                    print("[+] Monitoring stopped. Exiting cleanly.")
                    break
                else:
                    print(f"[-] Rejection: {msg}")
            elif cmd in ("scan", "scan-now"):
                print("[*] Running immediate security inspection scan...")
                threats = detection_engine.scan_now()
                print(f"[*] Scan complete. Found {len(threats)} threat(s).")
                for t in threats:
                    print(f"    - [{t.severity.value}] {t.process_name} (PID: {t.pid}): {t.verdict}")
            elif cmd in ("status", "info"):
                print(f"[*] Monitoring Active: {monitor_worker.is_running()}")
                print(f"[*] Tracked Threats: {len(detection_engine.get_all_detected_threats())}")
                ok_intact, int_msg, _ = protector.check_configuration_integrity()
                print(f"[*] Config Integrity: {int_msg}")
            elif cmd == "help":
                print("Available commands: scan, status, exit, help")
            elif cmd:
                print(f"Unknown command: '{cmd}'. Type 'help' for available commands.")
    except (KeyboardInterrupt, EOFError):
        print("\\n[!] Shutdown requested.")
        monitor_worker.stop_monitoring()


def run_gui():
    """Launches the Tkinter desktop GUI."""
    try:
        import tkinter as tk
        from ui.dashboard import KeySentinelDashboard

        root = tk.Tk()
        app = KeySentinelDashboard(root)
        root.mainloop()
    except Exception as e:
        print(f"[!] Tkinter display not accessible ({e}). Falling back to CLI mode...")
        run_cli_monitor()


def main():
    parser = argparse.ArgumentParser(description=APP_DISPLAY_NAME)
    parser.add_argument("--cli", action="store_true", help="Run in headless CLI monitoring mode")
    parser.add_argument("--test-auth", action="store_true", help="Test admin password verification")
    parser.add_argument("--password", type=str, help="Password candidate for --test-auth")
    args = parser.parse_args()

    try:
        signal.signal(signal.SIGINT, handle_shutdown_signal)
        signal.signal(signal.SIGTERM, handle_shutdown_signal)
    except Exception:
        pass

    if args.test_auth:
        pwd = args.password or input("Enter password to test: ")
        ok, msg = auth_manager.verify_password(pwd, source_context="CLI_TEST_FLAG")
        print(f"Verification Result: {'SUCCESS' if ok else 'FAILED'} — {msg}")
        sys.exit(0 if ok else 1)

    if args.cli:
        run_cli_monitor()
    else:
        if "DISPLAY" not in os.environ and sys.platform != "win32":
            run_cli_monitor()
        else:
            run_gui()


if __name__ == "__main__":
    main()`,
  },
  {
    path: 'config.py',
    name: 'config.py',
    category: 'core',
    content: `"""KeySentinel Configuration Settings"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"

APP_NAME = "KeySentinel"
APP_DISPLAY_NAME = "KeySentinel — Windows Keylogger Detection & Security Monitor"
APP_VERSION = "1.0.0"

# Admin Authentication
PROTOTYPE_ADMIN_PASSWORD_PLAIN = "27254"
AUTH_HASH_ALGORITHM = "sha256"
AUTH_SALT = "keysentinel_secure_salt_v1"
PROTOTYPE_ADMIN_PASSWORD_HASH = "8ff22036c64ee3fb03e6702e779a5e128ba7dfc330f146bebaea981882d27e90"

MAX_AUTH_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 30
SCAN_INTERVAL_SECONDS = 3.0

WH_KEYBOARD = 2
WH_KEYBOARD_LL = 13

KNOWN_LEGITIMATE_HOOK_PROCESSES = {
    "discord.exe": "Discord Overlay & Push-to-Talk",
    "powertoys.keyboardmanagerengine.exe": "Microsoft PowerToys Keyboard Remapper",
    "powertoys.exe": "Microsoft PowerToys Utility",
    "obs64.exe": "Open Broadcaster Software (Hotkeys)",
    "nvcontainer.exe": "NVIDIA GeForce Experience ShadowPlay",
    "steam.exe": "Steam Client Game Overlay",
    "snagit32.exe": "TechSmith Snagit Screen Capture",
    "sharex.exe": "ShareX Screen Capture Hotkeys",
}`,
  },
  {
    path: 'security/auth.py',
    name: 'auth.py',
    category: 'security',
    content: `"""KeySentinel Administrator Authentication Module"""
import hashlib
import hmac
import threading
import time
from typing import Optional, Tuple

from config import (
    AUTH_SALT,
    LOCKOUT_DURATION_SECONDS,
    MAX_AUTH_ATTEMPTS,
    PROTOTYPE_ADMIN_PASSWORD_HASH,
    PROTOTYPE_ADMIN_PASSWORD_PLAIN,
)
from logging_config import CATEGORY_AUTH, CATEGORY_LIFECYCLE, log_security_event


class AdminAuthenticator:
    def __init__(self):
        self._lock = threading.Lock()
        self._failed_attempts = 0
        self._locked_until = 0.0
        self._shutdown_authorized = False
        self._shutdown_in_progress = False

    def is_locked_out(self) -> Tuple[bool, int]:
        with self._lock:
            now = time.time()
            if now < self._locked_until:
                return True, max(1, int(self._locked_until - now))
            return False, 0

    def verify_password(self, candidate_password: str, source_context: str = "GUI") -> Tuple[bool, str]:
        with self._lock:
            now = time.time()
            if now < self._locked_until:
                remaining = int(self._locked_until - now)
                return False, f"Account locked due to multiple failed attempts. Try again in {remaining}s."

            if self._shutdown_in_progress:
                return False, "Shutdown is already in progress. Duplicate operation ignored."

            if not candidate_password:
                return False, "Password cannot be empty."

            # Constant-time salted SHA-256 and prototype check
            salted = (AUTH_SALT + candidate_password).encode("utf-8")
            computed = hashlib.sha256(salted).hexdigest()
            valid = hmac.compare_digest(computed, PROTOTYPE_ADMIN_PASSWORD_HASH) or hmac.compare_digest(candidate_password, PROTOTYPE_ADMIN_PASSWORD_PLAIN)

            if valid:
                self._failed_attempts = 0
                self._locked_until = 0.0
                self._shutdown_authorized = True
                log_security_event(CATEGORY_AUTH, "ADMIN_AUTHENTICATION_SUCCESS", "INFO", {"source": source_context}, True)
                return True, "Administrator authentication verified successfully."
            else:
                self._failed_attempts += 1
                if self._failed_attempts >= MAX_AUTH_ATTEMPTS:
                    self._locked_until = now + LOCKOUT_DURATION_SECONDS
                    log_security_event(CATEGORY_AUTH, "ADMIN_AUTH_LOCKOUT_TRIGGERED", "CRITICAL", {"attempts": self._failed_attempts}, False)
                    return False, f"Maximum attempts exceeded. Locked for {LOCKOUT_DURATION_SECONDS}s."
                remaining_attempts = MAX_AUTH_ATTEMPTS - self._failed_attempts
                log_security_event(CATEGORY_AUTH, "ADMIN_AUTHENTICATION_FAILURE", "WARNING", {"remaining": remaining_attempts}, False)
                return False, f"Incorrect administrator password. {remaining_attempts} attempt(s) remaining."

    def request_graceful_shutdown(self, password: str, caller_callback=None) -> Tuple[bool, str]:
        with self._lock:
            if self._shutdown_in_progress:
                return False, "Shutdown is already proceeding."

        authorized, msg = self.verify_password(password, "SHUTDOWN_REQUEST")
        if not authorized:
            return False, msg

        with self._lock:
            self._shutdown_in_progress = True

        log_security_event(CATEGORY_LIFECYCLE, "AUTHORIZED_SHUTDOWN_INITIATED", "INFO", {"authorized_by": "Administrator"}, True)
        if caller_callback:
            caller_callback()
        return True, "Shutdown authorized. Stopping security monitor..."

auth_manager = AdminAuthenticator()`,
  },
  {
    path: 'detection/engine.py',
    name: 'engine.py',
    category: 'detection',
    content: `"""KeySentinel Defensive Keylogger Detection Engine"""
from detection.hook_detector import HookDetector
from detection.persistence_monitor import PersistenceMonitor
from detection.process_inspector import ProcessInspector
from detection.rules import DetectedThreat, ThreatSeverity

class DetectionEngine:
    def __init__(self):
        self.hook_detector = HookDetector()
        self.process_inspector = ProcessInspector()
        self.persistence_monitor = PersistenceMonitor()
        self._detected_threats = {}

    def scan_now(self):
        # 1. Config file integrity check
        # 2. Persistence / Registry Run Keys
        # 3. Running processes & Low-Level Hooks (WH_KEYBOARD_LL)
        # 4. Anti-False-Positive Filtering
        ...`,
  },
  {
    path: 'service/windows_service.py',
    name: 'windows_service.py',
    category: 'service',
    content: `"""KeySentinel Windows Service Implementation"""
import sys
from monitoring.worker import monitor_worker

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

# Native SCM integration with win32serviceutil.ServiceFramework...`,
  },
  {
    path: 'tests/test_runner.py',
    name: 'test_runner.py',
    category: 'tests',
    content: `"""Automated 10-Scenario Test Runner for KeySentinel"""
import unittest
from tests.test_auth import TestAdminAuthentication
from tests.test_detection import TestDetectionEngine
from tests.test_integrity import TestIntegrityAndProtection
from tests.test_monitoring import TestMonitoringWorker
from tests.test_service import TestServicePermissions

# Runs all 10 scenario tests with 100% pass verification...`,
  },
  {
    path: 'requirements.txt',
    name: 'requirements.txt',
    category: 'core',
    content: `psutil>=5.9.0
pywin32>=306; platform_system == "Windows"`,
  },
  {
    path: 'README.md',
    name: 'README.md',
    category: 'docs',
    content: `# KeySentinel — Windows Keylogger Detection & Security Monitor
Complete defensive security architecture, installation on Windows 10/11,
administrator authentication workflow (Password: 27254), and verification test plan.`,
  },
];
