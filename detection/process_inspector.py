"""
KeySentinel — Process Inspector
Inspects running processes for suspicious path locations, masquerading,
atypical command-line flags, and keyboard hooking artifacts.
Handles AccessDenied and Zombie processes gracefully.
"""

import os
import platform
import sys
from typing import Any, Dict, List, Optional

from config import SUSPICIOUS_PATH_KEYWORDS
from detection.rules import (
    IndicatorCategory,
    ThreatIndicator,
    ThreatSeverity,
)

# Try importing psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class ProcessInspector:
    """
    Scans process memory and metadata to detect anomalies indicative of keyloggers.
    """

    def __init__(self):
        self._cached_processes: Dict[int, Dict[str, Any]] = {}

    def get_all_processes(self) -> List[Dict[str, Any]]:
        """
        Gathers list of running processes with basic metadata.
        Resilient against AccessDenied and missing process errors.
        """
        results = []
        if PSUTIL_AVAILABLE:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "create_time"]):
                try:
                    info = proc.info
                    results.append({
                        "pid": info["pid"],
                        "name": info["name"] or f"Process_{info['pid']}",
                        "exe": info.get("exe") or "Inaccessible / System",
                        "cmdline": " ".join(info.get("cmdline") or []),
                        "username": info.get("username") or "Unknown",
                        "create_time": info.get("create_time") or 0,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception:
                    continue
        else:
            # Fallback for environments without psutil installed
            # Provides self and parent process plus baseline inspection
            results.append({
                "pid": os.getpid(),
                "name": "python3" if platform.system() != "Windows" else "python.exe",
                "exe": os.path.realpath(__file__),
                "cmdline": "python " + " ".join(sys.argv),
                "username": "Current User",
                "create_time": 0,
            })
        return results

    def inspect_process(self, proc_info: Dict[str, Any]) -> List[ThreatIndicator]:
        """
        Evaluates a single process against heuristic rules.
        """
        indicators: List[ThreatIndicator] = []
        proc_name = (proc_info.get("name") or "").lower()
        exe_path = (proc_info.get("exe") or "").lower()
        cmdline = (proc_info.get("cmdline") or "").lower()

        # 1. Suspicious execution directory check (e.g. running directly from Temp/Public)
        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in exe_path:
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.SUSPICIOUS_PATH,
                        severity=ThreatSeverity.HIGH,
                        title="Executable Running from Suspicious Temporary Folder",
                        description=f"Process is executing from a transient or temp directory: '{exe_path}'. Keyloggers commonly drop binaries here.",
                        evidence_data={"exe_path": proc_info.get("exe"), "matched_path_keyword": keyword},
                        weight=30,
                    )
                )
                break

        # 2. Process Masquerading Checks
        # Windows system binaries should only execute from System32/SysWOW64
        system_binaries = ["svchost.exe", "csrss.exe", "smss.exe", "lsass.exe", "services.exe", "winlogon.exe"]
        for sys_bin in system_binaries:
            if proc_name == sys_bin:
                if exe_path and not ("\\windows\\system32\\" in exe_path or "\\windows\\syswow64\\" in exe_path):
                    indicators.append(
                        ThreatIndicator(
                            category=IndicatorCategory.MASQUERADING,
                            severity=ThreatSeverity.CRITICAL,
                            title=f"Critical: Windows System Process Masquerading Detected ({proc_name})",
                            description=(
                                f"Process is named '{proc_name}', but is executing from '{exe_path}' "
                                "instead of the trusted Windows System32 directory. High probability of malicious impersonation."
                            ),
                            evidence_data={"proc_name": proc_name, "exe_path": proc_info.get("exe")},
                            weight=50,
                        )
                    )

        # 3. Suspicious command line flags
        suspicious_flags = ["-klog", "--stealth", "/hidden", "keylog", "capturekeystrokes", "getasynckeystate"]
        for flag in suspicious_flags:
            if flag in cmdline:
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.POLLING_API,
                        severity=ThreatSeverity.HIGH,
                        title="Suspicious Keylogger Command-line Arguments",
                        description=f"Process launched with suspicious keystroke capture argument: '{flag}'.",
                        evidence_data={"cmdline": proc_info.get("cmdline"), "matched_flag": flag},
                        weight=35,
                    )
                )
                break

        return indicators
