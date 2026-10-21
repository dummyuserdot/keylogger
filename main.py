"""
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
    """
    Handles OS termination signals.
    """
    log_security_event(
        category=CATEGORY_LIFECYCLE,
        action="OS_SIGNAL_RECEIVED",
        severity="WARNING",
        details={"signal": signum},
        success=False,
    )
    print(f"\n[KeySentinel] Intercepted termination signal ({signum}).")
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

    # Check privileges
    is_admin = protector.is_running_as_admin()
    if is_admin:
        print("[+] Privilege: Running with Administrator privileges (Full Protection).")
    else:
        print("[!] Warning: Running with standard user privileges. Run as Admin for service defense.")

    # Initialize logging and hardening
    protector.harden_environment()
    log_security_event(
        category=CATEGORY_LIFECYCLE,
        action="APPLICATION_INITIALIZED_CLI",
        severity="INFO",
        details={"version": APP_VERSION, "admin": is_admin},
        success=True,
    )

    # Start background monitoring
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
        print("\n[!] Shutdown requested.")
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

    # Register OS signals
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
        # Check if GUI display is available
        if "DISPLAY" not in os.environ and sys.platform != "win32":
            run_cli_monitor()
        else:
            run_gui()


if __name__ == "__main__":
    main()
