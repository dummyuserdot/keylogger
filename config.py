"""
KeySentinel — Configuration Module
Contains non-secret application settings, detection rules, heuristics, and default paths.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"

# Ensure runtime directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Application Identity
APP_NAME = "KeySentinel"
APP_DISPLAY_NAME = "KeySentinel — Windows Keylogger Detection & Security Monitor"
APP_VERSION = "1.0.0"

# Admin Authentication Settings
# Prototype development password (as specified in requirements)
PROTOTYPE_ADMIN_PASSWORD_PLAIN = "27254"

# Salted SHA-256 hash configuration for isolated verification
AUTH_HASH_ALGORITHM = "sha256"
AUTH_SALT = "keysentinel_secure_salt_v1"
# Precomputed hash of (AUTH_SALT + "27254") using sha256
# echo -n "keysentinel_secure_salt_v127254" | sha256sum
PROTOTYPE_ADMIN_PASSWORD_HASH = "8ff22036c64ee3fb03e6702e779a5e128ba7dfc330f146bebaea981882d27e90"

# Rate Limiting & Lockout
MAX_AUTH_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 30  # lock after repeated failed attempts

# Detection Engine Heuristics & Thresholds
SCAN_INTERVAL_SECONDS = 3.0  # Background scan interval
PROCESS_CACHE_TTL_SECONDS = 10.0

# Suspicious Windows API Names often associated with keyboard interception
SUSPICIOUS_KEYBOARD_APIS = [
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetKeyboardState",
    "RegisterRawInputDevices",
    "GetRawInputData",
]

# Windows Low-Level Hook Types
WH_KEYBOARD = 2
WH_KEYBOARD_LL = 13
WH_MOUSE = 7
WH_MOUSE_LL = 14

# Suspicious file path locations (where background keyloggers often hide)
SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\recycle.bin\\",
    "/tmp/",
    "/var/tmp/",
]

# Known legitimate software known to use keyboard hooks (anti-false-positive list)
KNOWN_LEGITIMATE_HOOK_PROCESSES = {
    "discord.exe": "Discord Overlay & Push-to-Talk",
    "powertoys.keyboardmanagerengine.exe": "Microsoft PowerToys Keyboard Remapper",
    "powertoys.exe": "Microsoft PowerToys Utility",
    "obs64.exe": "Open Broadcaster Software (Hotkeys)",
    "nvcontainer.exe": "NVIDIA GeForce Experience ShadowPlay",
    "steam.exe": "Steam Client Game Overlay",
    "snagit32.exe": "TechSmith Snagit Screen Capture",
    "sharex.exe": "ShareX Screen Capture Hotkeys",
    "autohotkey.exe": "AutoHotkey Script Automation (User Configured)",
    "dwm.exe": "Desktop Window Manager (Core Windows Component)",
    "explorer.exe": "Windows Shell Explorer",
    "devenv.exe": "Microsoft Visual Studio",
    "code.exe": "Visual Studio Code",
}

# Windows Registry Run Persistence Keys to monitor
WINDOWS_STARTUP_REG_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
]

# Configuration Files to Protect
PROTECTED_CONFIG_FILE = CONFIG_DIR / "keysentinel_policy.json"
AUDIT_LOG_FILE = LOG_DIR / "keysentinel_security.log"

# Default Policy Content
DEFAULT_POLICY = {
    "version": "1.0",
    "detection_rules": {
        "detect_low_level_keyboard_hooks": True,
        "detect_raw_input_sinks": True,
        "detect_polling_getasynckeystate": True,
        "detect_unverified_startup_persistence": True,
        "detect_suspicious_temp_executables": True,
        "detect_process_masquerading": True,
        "strict_whitelisting_mode": False,
    },
    "severity_threshold": "MEDIUM",  # LOW, MEDIUM, HIGH, CRITICAL
    "quarantine_auto_action": False,
    "whitelisted_pids": [],
    "whitelisted_names": [
        "powertoys.keyboardmanagerengine.exe",
        "discord.exe",
        "obs64.exe",
    ],
}
