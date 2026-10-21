"""
KeySentinel — Keyboard Hook & Raw Input Detector
Monitors suspicious keyboard-capture APIs such as:
- SetWindowsHookEx (WH_KEYBOARD = 2, WH_KEYBOARD_LL = 13)
- RegisterRawInputDevices (RIDEV_INPUTSINK)
- GetAsyncKeyState continuous polling
"""

import os
import platform
from typing import Any, Dict, List, Optional, Tuple

from config import (
    KNOWN_LEGITIMATE_HOOK_PROCESSES,
    WH_KEYBOARD,
    WH_KEYBOARD_LL,
)
from detection.rules import (
    IndicatorCategory,
    ThreatIndicator,
    ThreatSeverity,
)

# Windows constants
RIDEV_INPUTSINK = 0x00000100
RIDEV_REMOVE = 0x00000001
HID_USAGE_PAGE_GENERIC = 0x01
HID_USAGE_KEYBOARD = 0x06


class HookDetector:
    """
    Defensive detector that identifies processes attempting to intercept
    keyboard messages at the Windows system level.
    """

    def __init__(self):
        self._simulated_hooks: List[Dict[str, Any]] = []
        self._is_windows = platform.system() == "Windows"

    def inject_test_hook_signal(self, pid: int, process_name: str, hook_type: int, module_name: str = "hook.dll"):
        """Utility for test suites and live simulations."""
        self._simulated_hooks.append({
            "pid": pid,
            "process_name": process_name,
            "hook_type": hook_type,
            "hook_name": "WH_KEYBOARD_LL" if hook_type == WH_KEYBOARD_LL else "WH_KEYBOARD",
            "module_name": module_name,
            "timestamp": os.times()[4],
        })

    def clear_test_hooks(self):
        """Clears simulated hook data."""
        self._simulated_hooks.clear()

    def inspect_process_for_keyboard_hooks(
        self,
        pid: int,
        process_name: str,
        loaded_modules: Optional[List[str]] = None,
    ) -> List[ThreatIndicator]:
        """
        Inspects whether a target process uses global keyboard capture hooks.
        Returns a list of ThreatIndicators if suspicious behaviors are found.
        """
        indicators: List[ThreatIndicator] = []
        proc_lower = process_name.lower()

        # Check for simulated test hooks
        for hook in self._simulated_hooks:
            if hook["pid"] == pid or hook["process_name"].lower() == proc_lower:
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.HOOK_API,
                        severity=ThreatSeverity.HIGH,
                        title=f"Low-Level Keyboard Hook Detected ({hook['hook_name']})",
                        description=(
                            f"Process installed a global {hook['hook_name']} (Type {hook['hook_type']}) "
                            f"hook via {hook.get('module_name', 'native code')}. This allows intercepting all keystrokes "
                            "across every running application."
                        ),
                        evidence_data=hook,
                        weight=45,
                    )
                )

        # On Windows: Check loaded modules for known keyboard hook DLLs or raw input handles
        if loaded_modules:
            suspicious_hook_dlls = ["user32.dll", "hook", "keylogger", "klog", "kbhook"]
            has_user32 = any("user32" in m.lower() for m in loaded_modules)
            has_custom_hook_dll = any("hook" in m.lower() and "windows" not in m.lower() for m in loaded_modules)

            if has_custom_hook_dll and proc_lower not in KNOWN_LEGITIMATE_HOOK_PROCESSES:
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.HOOK_API,
                        severity=ThreatSeverity.MEDIUM,
                        title="Suspicious Hooking Dynamic Library Loaded",
                        description="Process has loaded a custom library with hooking nomenclature into memory.",
                        evidence_data={"matched_modules": [m for m in loaded_modules if "hook" in m.lower()]},
                        weight=25,
                    )
                )

        # Check known legitimate hook processes (anti-false-positive mechanism)
        if proc_lower in KNOWN_LEGITIMATE_HOOK_PROCESSES:
            # Downgrade severity or clarify legitimacy
            for ind in indicators:
                if ind.category == IndicatorCategory.HOOK_API:
                    ind.severity = ThreatSeverity.LOW
                    ind.description += f" [BENIGN CONTEXT: Known legitimate tool: {KNOWN_LEGITIMATE_HOOK_PROCESSES[proc_lower]}]"
                    ind.weight = 10

        return indicators
