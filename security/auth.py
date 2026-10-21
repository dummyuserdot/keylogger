"""
KeySentinel — Administrator Authentication & Shutdown Authorization
Controls access to privileged operations such as monitoring termination.
Prototype password: '27254'
"""

import hashlib
import hmac
import threading
import time
from typing import Dict, Optional, Tuple

from config import (
    AUTH_SALT,
    LOCKOUT_DURATION_SECONDS,
    MAX_AUTH_ATTEMPTS,
    PROTOTYPE_ADMIN_PASSWORD_HASH,
    PROTOTYPE_ADMIN_PASSWORD_PLAIN,
)
from logging_config import (
    CATEGORY_AUTH,
    CATEGORY_LIFECYCLE,
    log_security_event,
)


class AdminAuthenticator:
    """
    Manages authentication state, rate limiting, and password verification.
    Ensures passwords are never persisted or printed into logs.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._failed_attempts = 0
        self._locked_until = 0.0
        self._shutdown_authorized = False
        self._shutdown_in_progress = False

    def is_locked_out(self) -> Tuple[bool, int]:
        """Check if authentication is currently locked out."""
        with self._lock:
            now = time.time()
            if now < self._locked_until:
                remaining = int(self._locked_until - now)
                return True, max(1, remaining)
            return False, 0

    def get_failed_attempts(self) -> int:
        """Get the number of failed attempts since last success."""
        with self._lock:
            return self._failed_attempts

    def verify_password(self, candidate_password: str, source_context: str = "GUI") -> Tuple[bool, str]:
        """
        Verifies the administrator password.

        Returns:
            Tuple[bool, str]: (is_authorized, status_message)
        """
        with self._lock:
            # Check lockout
            now = time.time()
            if now < self._locked_until:
                remaining = int(self._locked_until - now)
                log_security_event(
                    category=CATEGORY_AUTH,
                    action="AUTH_ATTEMPT_REJECTED_LOCKED_OUT",
                    severity="WARNING",
                    details={
                        "source": source_context,
                        "lockout_remaining_seconds": remaining,
                    },
                    success=False,
                )
                return False, f"Account locked due to multiple failed attempts. Try again in {remaining}s."

            if self._shutdown_in_progress:
                return False, "Shutdown is already in progress. Duplicate operation ignored."

            if not candidate_password:
                log_security_event(
                    category=CATEGORY_AUTH,
                    action="AUTH_ATTEMPT_EMPTY",
                    severity="WARNING",
                    details={"source": source_context},
                    success=False,
                )
                return False, "Password cannot be empty."

            # Verification routine
            # We verify via salted SHA-256 hash comparison and fallback check for prototype
            is_valid = self._verify_credential_internal(candidate_password)

            if is_valid:
                # Reset failure counters
                self._failed_attempts = 0
                self._locked_until = 0.0
                self._shutdown_authorized = True

                log_security_event(
                    category=CATEGORY_AUTH,
                    action="ADMIN_AUTHENTICATION_SUCCESS",
                    severity="INFO",
                    details={
                        "source": source_context,
                        "operation": "AUTHORIZED_ADMIN_ACTION",
                    },
                    success=True,
                )
                return True, "Administrator authentication verified successfully."

            else:
                self._failed_attempts += 1
                attempts_left = max(0, MAX_AUTH_ATTEMPTS - self._failed_attempts)

                if self._failed_attempts >= MAX_AUTH_ATTEMPTS:
                    self._locked_until = now + LOCKOUT_DURATION_SECONDS
                    log_security_event(
                        category=CATEGORY_AUTH,
                        action="ADMIN_AUTH_LOCKOUT_TRIGGERED",
                        severity="CRITICAL",
                        details={
                            "source": source_context,
                            "failed_attempts": self._failed_attempts,
                            "lockout_duration": LOCKOUT_DURATION_SECONDS,
                        },
                        success=False,
                    )
                    return (
                        False,
                        f"Authentication failed. Maximum attempts exceeded. Locked for {LOCKOUT_DURATION_SECONDS}s.",
                    )
                else:
                    log_security_event(
                        category=CATEGORY_AUTH,
                        action="ADMIN_AUTHENTICATION_FAILURE",
                        severity="WARNING",
                        details={
                            "source": source_context,
                            "consecutive_failures": self._failed_attempts,
                            "remaining_attempts": attempts_left,
                        },
                        success=False,
                    )
                    return False, f"Incorrect administrator password. {attempts_left} attempt(s) remaining."

    def _verify_credential_internal(self, candidate_password: str) -> bool:
        """
        Isolated credential verification logic.
        Uses constant-time comparison to protect against timing attacks.
        """
        # Method 1: Compare salted hash
        salted_candidate = (AUTH_SALT + candidate_password).encode("utf-8")
        computed_hash = hashlib.sha256(salted_candidate).hexdigest()

        hash_matches = hmac.compare_digest(computed_hash, PROTOTYPE_ADMIN_PASSWORD_HASH)

        # Method 2: Prototype fallback check for explicit prompt requirement ('27254')
        plain_matches = hmac.compare_digest(candidate_password, PROTOTYPE_ADMIN_PASSWORD_PLAIN)

        return hash_matches or plain_matches

    def request_graceful_shutdown(self, password: str, caller_callback=None) -> Tuple[bool, str]:
        """
        Executes the authorized shutdown gate.
        Debounced: ensures repeated button clicks cannot fire multiple shutdown routines.
        """
        with self._lock:
            if self._shutdown_in_progress:
                return False, "Shutdown is already proceeding."

        # Verify password
        authorized, msg = self.verify_password(password, source_context="SHUTDOWN_REQUEST")
        if not authorized:
            return False, msg

        with self._lock:
            self._shutdown_in_progress = True

        log_security_event(
            category=CATEGORY_LIFECYCLE,
            action="AUTHORIZED_SHUTDOWN_INITIATED",
            severity="INFO",
            details={"authorized_by": "Administrator", "target": "KeySentinel"},
            success=True,
        )

        if caller_callback:
            try:
                caller_callback()
            except Exception as e:
                log_security_event(
                    category=CATEGORY_LIFECYCLE,
                    action="SHUTDOWN_CALLBACK_ERROR",
                    severity="ERROR",
                    details={"error": str(e)},
                    success=False,
                )

        return True, "Shutdown authorized. Stopping security monitor..."

    def is_shutdown_in_progress(self) -> bool:
        with self._lock:
            return self._shutdown_in_progress

    def reset_state_for_testing(self):
        """Helper for test suites."""
        with self._lock:
            self._failed_attempts = 0
            self._locked_until = 0.0
            self._shutdown_authorized = False
            self._shutdown_in_progress = False


# Global singleton instance
auth_manager = AdminAuthenticator()
