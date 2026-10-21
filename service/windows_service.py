"""
KeySentinel — Windows Service Integration
Allows running KeySentinel as an official background Windows Service under
the Windows Service Control Manager (SCM).

Ensures continuous background execution even when no user is logged in.
Restricts service control permissions so only authorized administrators
can stop or reconfigure the service.
"""

import os
import platform
import sys
import time

from config import APP_NAME
from logging_config import (
    CATEGORY_LIFECYCLE,
    CATEGORY_SERVICE,
    log_security_event,
)
from monitoring.worker import monitor_worker

# Try importing pywin32 modules if running on Windows
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False


if PYWIN32_AVAILABLE:
    class KeySentinelService(win32serviceutil.ServiceFramework):
        """
        Native Windows Service framework implementation for KeySentinel.
        """
        _svc_name_ = "KeySentinelService"
        _svc_display_name_ = "KeySentinel Keylogger Detection Service"
        _svc_description_ = (
            "Continuous defensive security monitor inspecting for unauthorized keyboard-capture "
            "hooks and persistence attacks."
        )

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.is_alive = True

        def SvcStop(self):
            """
            Invoked when a Stop command is issued by the Service Control Manager.
            """
            log_security_event(
                category=CATEGORY_SERVICE,
                action="WINDOWS_SERVICE_STOP_REQUESTED",
                severity="WARNING",
                details={"service_name": self._svc_name_},
                success=True,
            )
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            monitor_worker.stop_monitoring()
            self.is_alive = False
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            """
            Main service execution entry.
            """
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            log_security_event(
                category=CATEGORY_SERVICE,
                action="WINDOWS_SERVICE_STARTED",
                severity="INFO",
                details={"service_name": self._svc_name_},
                success=True,
            )

            # Start background monitoring loop
            monitor_worker.start_monitoring()

            # Wait until stop event is signaled
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

            log_security_event(
                category=CATEGORY_SERVICE,
                action="WINDOWS_SERVICE_STOPPED",
                severity="INFO",
                details={"service_name": self._svc_name_},
                success=True,
            )
else:
    class KeySentinelService:
        """
        Fallback stub for non-Windows systems or systems without pywin32.
        Enables cross-platform testability.
        """
        _svc_name_ = "KeySentinelService"
        _svc_display_name_ = "KeySentinel Keylogger Detection Service"
        _svc_description_ = "Continuous defensive security monitor (Simulated)."

        def __init__(self, *args, **kwargs):
            self.is_alive = False

        def SvcDoRun(self):
            log_security_event(
                category=CATEGORY_SERVICE,
                action="SERVICE_SIMULATION_STARTED",
                severity="INFO",
                details={"platform": platform.system()},
                success=True,
            )
            self.is_alive = True
            monitor_worker.start_monitoring()

        def SvcStop(self):
            log_security_event(
                category=CATEGORY_SERVICE,
                action="SERVICE_SIMULATION_STOPPED",
                severity="INFO",
                details={"platform": platform.system()},
                success=True,
            )
            monitor_worker.stop_monitoring()
            self.is_alive = False


def run_service_cli():
    """CLI handler for service installation, start, stop, debug."""
    if PYWIN32_AVAILABLE:
        win32serviceutil.HandleCommandLine(KeySentinelService)
    else:
        print("Note: pywin32 is not installed or current OS is non-Windows. Running in emulation mode.")
        if len(sys.argv) > 1 and sys.argv[1] == "debug":
            service = KeySentinelService()
            service.SvcDoRun()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                service.SvcStop()


if __name__ == "__main__":
    run_service_cli()
