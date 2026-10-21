"""
KeySentinel — Unauthorized Termination & Tamper Protection
Implements defensive Windows access control enforcement, configuration file
integrity hashing, and privilege assessment.
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import (
    CONFIG_DIR,
    DEFAULT_POLICY,
    LOG_DIR,
    PROTECTED_CONFIG_FILE,
)
from logging_config import (
    CATEGORY_INTEGRITY,
    CATEGORY_SERVICE,
    log_security_event,
)


class SecurityProtector:
    """
    Manages system-level security protections:
    - Integrity baseline calculation & auditing
    - Directory permission verification
    - Administrator privilege validation
    """

    def __init__(self):
        self._policy_hash: Optional[str] = None
        self._initialize_default_policy()
        self.update_policy_baseline()

    def is_running_as_admin(self) -> bool:
        """
        Checks whether the process runs with elevated Administrator / root privileges.
        Uses Windows ctypes Shell32 API when on Windows.
        """
        if platform.system() == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            try:
                return os.geteuid() == 0
            except AttributeError:
                return False

    def _initialize_default_policy(self):
        """Ensures the policy file exists with default parameters."""
        if not PROTECTED_CONFIG_FILE.exists():
            try:
                CONFIG_DIR.mkdir(parents=True, exist_ok=True)
                with open(PROTECTED_CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(DEFAULT_POLICY, f, indent=2)
                log_security_event(
                    category=CATEGORY_INTEGRITY,
                    action="POLICY_INITIALIZED",
                    severity="INFO",
                    details={"file": str(PROTECTED_CONFIG_FILE)},
                    success=True,
                )
            except Exception as e:
                log_security_event(
                    category=CATEGORY_INTEGRITY,
                    action="POLICY_INIT_FAILED",
                    severity="ERROR",
                    details={"error": str(e)},
                    success=False,
                )

    def calculate_file_hash(self, file_path: Path) -> Optional[str]:
        """Calculates SHA-256 checksum of a target file."""
        if not file_path.exists():
            return None
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def update_policy_baseline(self):
        """Records current hash as authorized baseline."""
        self._policy_hash = self.calculate_file_hash(PROTECTED_CONFIG_FILE)

    def check_configuration_integrity(self) -> Tuple[bool, str, Optional[Dict[str, str]]]:
        """
        Checks whether protected configuration has been modified without authorization.
        Returns: (is_intact, message, details)
        """
        if not PROTECTED_CONFIG_FILE.exists():
            msg = f"ALERT: Protected configuration file {PROTECTED_CONFIG_FILE.name} has been deleted or moved!"
            log_security_event(
                category=CATEGORY_INTEGRITY,
                action="PROTECTED_CONFIG_DELETED",
                severity="CRITICAL",
                details={"file": str(PROTECTED_CONFIG_FILE)},
                success=False,
            )
            return False, msg, {"status": "FILE_MISSING"}

        current_hash = self.calculate_file_hash(PROTECTED_CONFIG_FILE)
        if self._policy_hash is not None and current_hash != self._policy_hash:
            msg = "ALERT: Configuration file integrity check failed! Unauthorized modification detected."
            details = {
                "file": str(PROTECTED_CONFIG_FILE),
                "expected_hash": self._policy_hash,
                "detected_hash": current_hash,
            }
            log_security_event(
                category=CATEGORY_INTEGRITY,
                action="UNAUTHORIZED_CONFIG_MODIFICATION_DETECTED",
                severity="CRITICAL",
                details=details,
                success=False,
            )
            return False, msg, details

        return True, "Configuration integrity verified.", {"status": "INTACT", "hash": current_hash}

    def apply_directory_permissions(self, target_dir: Path) -> Tuple[bool, str]:
        """
        Applies restrictive Access Control Lists (ACLs) to a directory.
        On Windows: Uses icacls to grant Full Control only to SYSTEM and Administrators,
        preventing unauthorized standard users from deleting or altering logs/configs.
        """
        if platform.system() == "Windows":
            try:
                # Command: icacls <dir> /inheritance:r /grant:r Administrators:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F
                cmd = [
                    "icacls",
                    str(target_dir),
                    "/inheritance:r",
                    "/grant:r",
                    "Administrators:(OI)(CI)F",
                    "/grant:r",
                    "SYSTEM:(OI)(CI)F",
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    log_security_event(
                        category=CATEGORY_SERVICE,
                        action="WINDOWS_ACL_APPLIED",
                        severity="INFO",
                        details={"directory": str(target_dir)},
                        success=True,
                    )
                    return True, "Windows ACLs restricted to Administrators & SYSTEM."
                else:
                    return False, f"icacls reported non-zero return code: {res.stderr.strip()}"
            except Exception as e:
                return False, f"Windows ACL update skipped or failed: {str(e)}"
        else:
            # POSIX permission hardening fallback (chmod 700)
            try:
                os.chmod(target_dir, 0o700)
                return True, "Directory permissions set to 0700 (Owner-only)."
            except Exception as e:
                return False, f"POSIX chmod failed: {str(e)}"

    def harden_environment(self) -> Dict[str, Any]:
        """Runs overall environment hardening checks and permissions setup."""
        results = {}
        is_admin = self.is_running_as_admin()
        results["is_admin"] = is_admin

        if not is_admin:
            results["warning"] = (
                "KeySentinel is running with standard user privileges. "
                "For full termination defense and Windows Service monitoring, "
                "run with elevated Administrator permissions."
            )
            log_security_event(
                category=CATEGORY_SERVICE,
                action="INSUFFICIENT_PRIVILEGES_WARNING",
                severity="WARNING",
                details={"status": "NON_ELEVATED"},
                success=False,
            )
        else:
            # Apply directory hardening
            log_res = self.apply_directory_permissions(LOG_DIR)
            cfg_res = self.apply_directory_permissions(CONFIG_DIR)
            results["acl_hardening"] = {"logs": log_res, "config": cfg_res}

        integrity_ok, msg, details = self.check_configuration_integrity()
        results["integrity"] = {"ok": integrity_ok, "message": msg, "details": details}
        return results


# Global singleton instance
protector = SecurityProtector()
