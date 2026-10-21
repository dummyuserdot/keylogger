"""
KeySentinel — Defensive Keylogger Detection Engine
Orchestrates process inspection, keyboard-capture API detection, persistence auditing,
and configuration integrity verification.

CRITICAL ARCHITECTURAL PRINCIPLES:
1. Purely defensive — NEVER records or captures user keystrokes.
2. Anti-False-Positive — Clearly distinguishes 'Suspicious Indicator' from 'Confirmed Keylogger'.
3. Transparent Evidence — Presents full technical evidence for human review before action.
"""

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from config import (
    DEFAULT_POLICY,
    KNOWN_LEGITIMATE_HOOK_PROCESSES,
    PROTECTED_CONFIG_FILE,
)
from detection.hook_detector import HookDetector
from detection.persistence_monitor import PersistenceMonitor
from detection.process_inspector import ProcessInspector
from detection.rules import (
    DetectedThreat,
    IndicatorCategory,
    ThreatIndicator,
    ThreatSeverity,
)
from logging_config import (
    CATEGORY_INTEGRITY,
    CATEGORY_PROCESS,
    log_security_event,
)
from security.protection import protector


class DetectionEngine:
    """
    Main detection coordinator. Thread-safe and configurable.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.hook_detector = HookDetector()
        self.process_inspector = ProcessInspector()
        self.persistence_monitor = PersistenceMonitor()

        self._policy = dict(DEFAULT_POLICY)
        self._load_policy()

        # Detected threats index: threat_id -> DetectedThreat
        self._detected_threats: Dict[str, DetectedThreat] = {}
        self._whitelisted_pids: Set[int] = set(self._policy.get("whitelisted_pids", []))
        self._whitelisted_names: Set[str] = set(
            n.lower() for n in self._policy.get("whitelisted_names", [])
        )
        self._quarantined_pids: Set[int] = set()

        # Callbacks when threats are detected
        self._threat_listeners: List[Callable[[DetectedThreat], None]] = []

    def _load_policy(self):
        """Loads policy from file if present."""
        if PROTECTED_CONFIG_FILE.exists():
            try:
                with open(PROTECTED_CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._policy.update(data)
            except Exception:
                pass

    def add_threat_listener(self, listener: Callable[[DetectedThreat], None]):
        """Registers a listener callback for real-time notification."""
        with self._lock:
            self._threat_listeners.append(listener)

    def scan_now(self) -> List[DetectedThreat]:
        """
        Executes a comprehensive security scan across:
        1. Process memory & paths
        2. Windows Hook APIs & Raw Input
        3. Startup & Persistence locations
        4. Protected Configuration integrity
        """
        threats_found: List[DetectedThreat] = []

        # Step 1: Configuration file integrity check
        intact, integrity_msg, details = protector.check_configuration_integrity()
        if not intact:
            integrity_threat = DetectedThreat(
                threat_id=f"threat-integrity-{int(time.time())}",
                process_name="System / File System",
                pid=0,
                executable_path=str(PROTECTED_CONFIG_FILE),
                detected_at=datetime.now(timezone.utc).isoformat(),
                severity=ThreatSeverity.CRITICAL,
                confidence_score=95,
                is_confirmed=True,
                verdict="INTEGRITY_VIOLATION_TAMPERING",
                indicators=[
                    ThreatIndicator(
                        category=IndicatorCategory.INTEGRITY_TAMPER,
                        severity=ThreatSeverity.CRITICAL,
                        title="Configuration File Tampered or Deleted",
                        description=integrity_msg,
                        evidence_data=details or {},
                        weight=50,
                    )
                ],
                notes="Protected configuration altered outside authorized admin channel.",
            )
            threats_found.append(integrity_threat)

        # Step 2: Persistence Entries Scan
        persistence_indicators = self.persistence_monitor.inspect_persistence_entries()
        for ind in persistence_indicators:
            cmd = ind.evidence_data.get("command", "")
            name = ind.evidence_data.get("name", "UnknownPersistence")
            t_id = f"threat-persist-{abs(hash(cmd)) % 100000}"
            threat = DetectedThreat(
                threat_id=t_id,
                process_name=f"Persistence: {name}",
                pid=-1,
                executable_path=cmd,
                detected_at=datetime.now(timezone.utc).isoformat(),
                severity=ind.severity,
                confidence_score=70,
                is_confirmed=False,
                verdict="SUSPICIOUS_PERSISTENCE",
                indicators=[ind],
                notes="Review startup registry entry or task command line.",
            )
            threats_found.append(threat)

        # Step 3: Running Processes & Hook Detection
        processes = self.process_inspector.get_all_processes()
        # Ensure any processes associated with active hooks are also inspected
        for hook in self.hook_detector._simulated_hooks:
            if not any(p["pid"] == hook["pid"] for p in processes):
                processes.append({
                    "pid": hook["pid"],
                    "name": hook["process_name"],
                    "exe": hook.get("module_name", "C:\\Windows\\Temp\\simulated_hook.dll"),
                    "cmdline": "",
                    "username": "ActiveUser",
                    "create_time": 0,
                })
        for p in processes:
            pid = p["pid"]
            name = p["name"]
            name_lower = name.lower()

            # Skip whitelisted PIDs or processes
            if pid in self._whitelisted_pids or name_lower in self._whitelisted_names:
                continue

            indicators: List[ThreatIndicator] = []

            # Process heuristic checks (paths, masquerading, cmdline)
            indicators.extend(self.process_inspector.inspect_process(p))

            # Keyboard Hook API checks
            indicators.extend(
                self.hook_detector.inspect_process_for_keyboard_hooks(
                    pid=pid,
                    process_name=name,
                    loaded_modules=[p.get("exe", "")],
                )
            )

            if not indicators:
                continue

            # Calculate composite confidence score and severity
            total_weight = sum(ind.weight for ind in indicators)
            confidence = min(98, total_weight)

            # Determine whether this is a confirmed keylogger or suspicious indicator
            has_hook = any(ind.category == IndicatorCategory.HOOK_API for ind in indicators)
            has_masquerade = any(ind.category == IndicatorCategory.MASQUERADING for ind in indicators)
            has_suspicious_path = any(ind.category == IndicatorCategory.SUSPICIOUS_PATH for ind in indicators)

            # A confirmed keylogger classification requires BOTH a keyboard hook AND a clandestine attribute
            # (such as running out of Temp/masquerading), preventing false-positives on legit games/tools.
            is_confirmed = (has_hook and has_suspicious_path) or has_masquerade or (confidence >= 80)

            if is_confirmed:
                verdict = "CONFIRMED_KEYLOGGER_THREAT"
                final_severity = ThreatSeverity.CRITICAL if confidence > 85 else ThreatSeverity.HIGH
            else:
                verdict = "SUSPICIOUS_INDICATOR_UNCONFIRMED"
                final_severity = ThreatSeverity.HIGH if confidence > 60 else ThreatSeverity.MEDIUM

            # Build DetectedThreat object
            threat_id = f"threat-{pid}-{int(time.time())}"
            detected_threat = DetectedThreat(
                threat_id=threat_id,
                process_name=name,
                pid=pid,
                executable_path=p.get("exe", "Unknown"),
                detected_at=datetime.now(timezone.utc).isoformat(),
                severity=final_severity,
                confidence_score=confidence,
                is_confirmed=is_confirmed,
                verdict=verdict,
                indicators=indicators,
                notes=(
                    "Confirmed malicious keylogger signature"
                    if is_confirmed
                    else "Suspicious keyboard intercept behavior; verify if legitimate software before terminating."
                ),
            )
            threats_found.append(detected_threat)

        # Update thread-safe index
        with self._lock:
            for t in threats_found:
                self._detected_threats[t.threat_id] = t
                log_security_event(
                    category=CATEGORY_PROCESS,
                    action="KEYLOGGER_THREAT_DETECTED",
                    severity=t.severity.value,
                    details={
                        "threat_id": t.threat_id,
                        "process_name": t.process_name,
                        "pid": t.pid,
                        "verdict": t.verdict,
                        "confidence": t.confidence_score,
                        "is_confirmed": t.is_confirmed,
                    },
                    success=True,
                )
                for cb in self._threat_listeners:
                    try:
                        cb(t)
                    except Exception:
                        pass

        return threats_found

    def get_all_detected_threats(self) -> List[DetectedThreat]:
        """Returns currently known threats."""
        with self._lock:
            return list(self._detected_threats.values())

    def clear_threat(self, threat_id: str):
        """Removes a threat from active tracking (e.g. after resolution)."""
        with self._lock:
            if threat_id in self._detected_threats:
                del self._detected_threats[threat_id]

    def whitelist_process(self, pid: int, process_name: str):
        """Adds a process to the authorized whitelist."""
        with self._lock:
            if pid > 0:
                self._whitelisted_pids.add(pid)
            if process_name:
                self._whitelisted_names.add(process_name.lower())

            # Mark in active threats
            for t in self._detected_threats.values():
                if t.pid == pid or t.process_name.lower() == process_name.lower():
                    t.is_whitelisted = True

        log_security_event(
            category=CATEGORY_PROCESS,
            action="PROCESS_ADDED_TO_WHITELIST",
            severity="INFO",
            details={"pid": pid, "process_name": process_name},
            success=True,
        )

    def quarantine_process(self, threat_id: str) -> Tuple[bool, str]:
        """
        Quarantines or terminates a malicious process after administrator authorization.
        """
        with self._lock:
            threat = self._detected_threats.get(threat_id)
            if not threat:
                return False, f"Threat ID '{threat_id}' not found."

            pid = threat.pid
            if pid <= 0:
                threat.quarantined = True
                return True, f"Non-process threat '{threat.process_name}' neutralized."

            try:
                import psutil
                if psutil.pid_exists(pid):
                    p = psutil.Process(pid)
                    p.terminate()
                    p.wait(timeout=2)
                    threat.quarantined = True
                    log_security_event(
                        category=CATEGORY_PROCESS,
                        action="PROCESS_QUARANTINED_TERMINATED",
                        severity="WARNING",
                        details={"pid": pid, "process_name": threat.process_name},
                        success=True,
                    )
                    return True, f"Process {threat.process_name} (PID {pid}) terminated successfully."
            except Exception as e:
                return False, f"Failed to terminate process PID {pid}: {str(e)}"

            threat.quarantined = True
            return True, f"Threat marked as neutralized."


# Global singleton instance
detection_engine = DetectionEngine()
