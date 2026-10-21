"""
KeySentinel — Detection Rules & Threat Severity Classification
Defines the heuristic models, confidence thresholds, and indicator types.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IndicatorCategory(str, Enum):
    HOOK_API = "KEYBOARD_HOOK_API"
    RAW_INPUT = "RAW_INPUT_CAPTURE"
    POLLING_API = "ASYNC_KEYSTATE_POLLING"
    SUSPICIOUS_PATH = "SUSPICIOUS_EXECUTABLE_PATH"
    PERSISTENCE = "STARTUP_PERSISTENCE"
    MASQUERADING = "PROCESS_MASQUERADING"
    HIDDEN_WINDOW = "HIDDEN_BACKGROUND_WINDOW"
    INTEGRITY_TAMPER = "CONFIGURATION_TAMPER"


@dataclass
class ThreatIndicator:
    """
    A single observed anomaly or technical evidence point.
    """
    category: IndicatorCategory
    severity: ThreatSeverity
    title: str
    description: str
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    weight: int = 10  # Scoring weight (10 to 50)


@dataclass
class DetectionRule:
    """
    A configurable detection rule.
    """
    id: str
    name: str
    enabled: bool = True
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    description: str = ""


@dataclass
class DetectedThreat:
    """
    Comprehensive representation of a potential keylogger threat.
    Includes process metadata, evidence breakdown, and clear distinction between
    a suspected anomaly vs confirmed malicious keylogger.
    """
    threat_id: str
    process_name: str
    pid: int
    executable_path: str
    detected_at: str
    severity: ThreatSeverity
    confidence_score: int  # 0 to 100
    is_confirmed: bool  # False = Suspicious Indicator, True = High Confidence Keylogger
    verdict: str  # e.g., "SUSPICIOUS_HOOK", "POTENTIAL_KEYLOGGER", "VERIFIED_THREAT"
    indicators: List[ThreatIndicator] = field(default_factory=list)
    is_whitelisted: bool = False
    quarantined: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "process_name": self.process_name,
            "pid": self.pid,
            "executable_path": self.executable_path,
            "detected_at": self.detected_at,
            "severity": self.severity.value,
            "confidence_score": self.confidence_score,
            "is_confirmed": self.is_confirmed,
            "verdict": self.verdict,
            "is_whitelisted": self.is_whitelisted,
            "quarantined": self.quarantined,
            "notes": self.notes,
            "indicators": [
                {
                    "category": ind.category.value,
                    "severity": ind.severity.value,
                    "title": ind.title,
                    "description": ind.description,
                    "evidence_data": ind.evidence_data,
                    "weight": ind.weight,
                }
                for ind in self.indicators
            ],
        }
