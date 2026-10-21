"""
KeySentinel — Persistence & Startup Location Monitor
Monitors Windows Registry Run keys, Startup folders, and persistence mechanisms
frequently abused by keyloggers to survive system reboots.
"""

import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import (
    SUSPICIOUS_PATH_KEYWORDS,
    WINDOWS_STARTUP_REG_KEYS,
)
from detection.rules import (
    IndicatorCategory,
    ThreatIndicator,
    ThreatSeverity,
)

# Check winreg on Windows
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


class PersistenceMonitor:
    """
    Scans auto-start points to identify suspicious persistence entries.
    """

    def __init__(self):
        self._simulated_entries: List[Dict[str, Any]] = []

    def inject_test_persistence_entry(self, name: str, command: str, location: str):
        """Helper to inject simulated startup entries for test verification."""
        self._simulated_entries.append({
            "name": name,
            "command": command,
            "location": location,
        })

    def clear_test_entries(self):
        self._simulated_entries.clear()

    def scan_startup_entries(self) -> List[Dict[str, Any]]:
        """
        Gathers list of programs configured to launch automatically on Windows boot.
        """
        entries = list(self._simulated_entries)

        if WINREG_AVAILABLE:
            # Query HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE Run keys
            for root_key_val, root_name in [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]:
                for subkey in WINDOWS_STARTUP_REG_KEYS:
                    try:
                        with winreg.OpenKey(root_key_val, subkey, 0, winreg.KEY_READ) as key:
                            idx = 0
                            while True:
                                try:
                                    name, val, _ = winreg.EnumValue(key, idx)
                                    entries.append({
                                        "name": name,
                                        "command": str(val),
                                        "location": f"{root_name}\\{subkey}",
                                    })
                                    idx += 1
                                except OSError:
                                    break
                    except (FileNotFoundError, PermissionError):
                        continue
                    except Exception:
                        continue

        # Check Windows Startup folder
        if platform.system() == "Windows":
            appdata = os.environ.get("APPDATA")
            if appdata:
                startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if startup_dir.exists():
                    for item in startup_dir.iterdir():
                        if item.is_file() and not item.name.startswith("."):
                            entries.append({
                                "name": item.name,
                                "command": str(item),
                                "location": "User Startup Folder",
                            })

        return entries

    def inspect_persistence_entries(self) -> List[ThreatIndicator]:
        """
        Audits startup entries for suspicious characteristics.
        """
        indicators: List[ThreatIndicator] = []
        entries = self.scan_startup_entries()

        for entry in entries:
            cmd = entry.get("command", "").lower()
            name = entry.get("name", "")
            loc = entry.get("location", "")

            # Check if pointing to temporary or unverified user folders
            for keyword in SUSPICIOUS_PATH_KEYWORDS:
                if keyword in cmd:
                    indicators.append(
                        ThreatIndicator(
                            category=IndicatorCategory.PERSISTENCE,
                            severity=ThreatSeverity.HIGH,
                            title=f"Suspicious Startup Persistence in {name}",
                            description=(
                                f"Auto-start entry '{name}' located at '{loc}' points to executable in "
                                f"suspicious path: '{cmd}'."
                            ),
                            evidence_data=entry,
                            weight=35,
                        )
                    )
                    break

            # Check for suspicious script or hidden execution flags
            if any(s in cmd for s in ["powershell.exe -w hidden", "wscript.exe", "cscript.exe", "mshta.exe"]):
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.PERSISTENCE,
                        severity=ThreatSeverity.MEDIUM,
                        title=f"Hidden Script Persistence Entry ({name})",
                        description=f"Auto-start entry uses hidden execution or scripting engine: '{cmd}'.",
                        evidence_data=entry,
                        weight=25,
                    )
                )

        return indicators
