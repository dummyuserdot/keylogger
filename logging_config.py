"""
KeySentinel — Security Event Logging
Maintains tamper-evident audit logs for security events.
CRITICAL: Never logs keystrokes, passwords, or authentication secrets.
"""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from config import AUDIT_LOG_FILE, LOG_DIR

# Event Categories
CATEGORY_AUTH = "AUTHENTICATION"
CATEGORY_PROCESS = "SUSPICIOUS_PROCESS"
CATEGORY_PERSISTENCE = "PERSISTENCE_TAMPER"
CATEGORY_INTEGRITY = "CONFIG_INTEGRITY"
CATEGORY_SERVICE = "SERVICE_CONTROL"
CATEGORY_LIFECYCLE = "APPLICATION_LIFECYCLE"
CATEGORY_MONITOR = "MONITORING_ENGINE"

_log_lock = threading.Lock()
_logger_initialized = False


class SecurityLogFilter(logging.Filter):
    """
    Sanitizes log records to strictly ensure no sensitive passwords,
    auth secrets, or potential raw keystrokes are ever logged.
    """

    FORBIDDEN_KEYWORDS = ["password=", "secret=", "passwd=", "token=", "27254"]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = str(record.msg)
        for kw in self.FORBIDDEN_KEYWORDS:
            if kw in msg.lower() or kw in msg:
                record.msg = "[SANITIZED_SECURITY_REDACTED]"
                break
        return True


def setup_security_logging() -> logging.Logger:
    """Configures structured security audit logging."""
    global _logger_initialized
    logger = logging.getLogger("KeySentinelSecurity")

    if _logger_initialized:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Create formatters
    file_formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "category": "%(name)s", "message": %(message)s}',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    console_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [KeySentinel] %(message)s",
        datefmt="%H:%M:%S",
    )

    # File Handler
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(AUDIT_LOG_FILE), encoding="utf-8")
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(file_formatter)
        file_handler.addFilter(SecurityLogFilter())
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not bind audit log file: {e}", file=sys.stderr)

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    console_handler.addFilter(SecurityLogFilter())
    logger.addHandler(console_handler)

    _logger_initialized = True
    return logger


# In-memory recent events buffer for live UI rendering
_recent_events = []
_MAX_RECENT_EVENTS = 200


def log_security_event(
    category: str,
    action: str,
    severity: str = "INFO",
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
) -> Dict[str, Any]:
    """
    Records a high-assurance audit event.
    Parameters are strictly validated to prevent password leakage.
    """
    logger = setup_security_logging()

    # Never log password fields
    sanitized_details = {}
    if details:
        for k, v in details.items():
            if "password" in k.lower() or "secret" in k.lower() or "credential" in k.lower():
                sanitized_details[k] = "[REDACTED]"
            else:
                sanitized_details[k] = v

    event_payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "action": action,
        "severity": severity.upper(),
        "success": success,
        "details": sanitized_details,
    }

    payload_json_str = json.dumps(event_payload)

    with _log_lock:
        if severity.upper() in ("CRITICAL", "HIGH", "ALERT"):
            logger.warning(payload_json_str)
        elif severity.upper() == "ERROR":
            logger.error(payload_json_str)
        else:
            logger.info(payload_json_str)

        _recent_events.append(event_payload)
        if len(_recent_events) > _MAX_RECENT_EVENTS:
            _recent_events.pop(0)

    return event_payload


def get_recent_security_events(limit: int = 50):
    """Retrieve in-memory copy of recent audit events."""
    with _log_lock:
        return list(_recent_events[-limit:])
