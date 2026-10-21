"""
KeySentinel — Service Manager & Access Control
Provides administrative controls to install, query, start, and stop
the KeySentinel Windows Service using Windows Service Control Manager (SCM).
Ensures appropriate security warnings on privilege denial.
"""

import platform
import subprocess
from typing import Any, Dict, Tuple

from config import APP_NAME
from logging_config import (
    CATEGORY_SERVICE,
    log_security_event,
)
from security.protection import protector

SERVICE_NAME = "KeySentinelService"


class ServiceManager:
    """
    Manages Windows Service status, installation, and access validation.
    """

    def is_windows(self) -> bool:
        return platform.system() == "Windows"

    def get_service_status(self) -> Dict[str, Any]:
        """
        Queries current status from Windows Service Control Manager.
        """
        if not self.is_windows():
            return {
                "installed": False,
                "status": "NOT_SUPPORTED_PLATFORM",
                "message": f"Windows Service requires Windows OS (Current: {platform.system()})",
                "can_control": False,
            }

        try:
            cmd = ["sc", "query", SERVICE_NAME]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if "FAILED 1060" in res.stderr or "FAILED 1060" in res.stdout:
                return {
                    "installed": False,
                    "status": "NOT_INSTALLED",
                    "message": "Service is not installed on this machine.",
                    "can_control": protector.is_running_as_admin(),
                }

            if "STATE" in res.stdout:
                if "RUNNING" in res.stdout:
                    status = "RUNNING"
                elif "STOPPED" in res.stdout:
                    status = "STOPPED"
                elif "START_PENDING" in res.stdout:
                    status = "STARTING"
                elif "STOP_PENDING" in res.stdout:
                    status = "STOPPING"
                else:
                    status = "UNKNOWN"

                return {
                    "installed": True,
                    "status": status,
                    "message": f"Service is currently {status}.",
                    "can_control": protector.is_running_as_admin(),
                }
            return {
                "installed": False,
                "status": "UNKNOWN",
                "message": res.stdout.strip(),
                "can_control": protector.is_running_as_admin(),
            }
        except subprocess.TimeoutExpired:
            return {"installed": False, "status": "TIMEOUT", "message": "SCM query timed out."}
        except Exception as e:
            return {"installed": False, "status": "ERROR", "message": str(e)}

    def install_service(self, python_exe: str, script_path: str) -> Tuple[bool, str]:
        """
        Installs the Windows Service via Service Control Manager.
        Requires Administrator privileges.
        """
        if not protector.is_running_as_admin():
            msg = "Privilege Denied: Installing a Windows Service requires an elevated Administrator prompt."
            log_security_event(
                category=CATEGORY_SERVICE,
                action="SERVICE_INSTALL_DENIED_ELEVATION",
                severity="ERROR",
                details={"status": "INSUFFICIENT_PRIVILEGES"},
                success=False,
            )
            return False, msg

        if not self.is_windows():
            return False, "Windows Service installation requires Windows OS."

        try:
            cmd = [
                "sc",
                "create",
                SERVICE_NAME,
                f"binPath= \"{python_exe}\" \"{script_path}\"",
                "start= auto",
                f"DisplayName= KeySentinel Keylogger Detection Service",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                # Restrict permissions using Security Descriptor (SDDL) so only Admin/SYSTEM can stop it
                # SDDL: D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
                lock_cmd = [
                    "sc",
                    "sdset",
                    SERVICE_NAME,
                    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)",
                ]
                subprocess.run(lock_cmd, capture_output=True, text=True, timeout=5)

                log_security_event(
                    category=CATEGORY_SERVICE,
                    action="SERVICE_INSTALLED_AND_PROTECTED",
                    severity="INFO",
                    details={"service_name": SERVICE_NAME},
                    success=True,
                )
                return True, "KeySentinel Windows Service installed and access controls hardened successfully."
            else:
                return False, f"Failed to install service: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"Error installing service: {str(e)}"

    def request_service_stop(self) -> Tuple[bool, str]:
        """
        Requests stop from Windows Service Control Manager.
        """
        if not protector.is_running_as_admin():
            msg = (
                "Access Denied: Standard users cannot stop the KeySentinel Windows Service. "
                "Only authorized Administrators with the proper credentials may stop this monitor."
            )
            log_security_event(
                category=CATEGORY_SERVICE,
                action="UNAUTHORIZED_SERVICE_STOP_DENIED",
                severity="WARNING",
                details={"service_name": SERVICE_NAME},
                success=False,
            )
            return False, msg

        if not self.is_windows():
            return True, "Service stop simulation succeeded."

        try:
            cmd = ["sc", "stop", SERVICE_NAME]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                log_security_event(
                    category=CATEGORY_SERVICE,
                    action="SERVICE_STOPPED_BY_ADMIN",
                    severity="INFO",
                    details={"service_name": SERVICE_NAME},
                    success=True,
                )
                return True, "Service stop command transmitted to SCM."
            else:
                return False, f"SCM error: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"Failed to communicate with SCM: {str(e)}"


# Global singleton instance
service_manager = ServiceManager()
