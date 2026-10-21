"""
KeySentinel — Background Monitoring Worker
Runs defensive detection cycles in a background worker thread.
Maintains thread safety, prevents duplicate threads, and shuts down cleanly.
"""

import threading
import time
from enum import Enum
from typing import Callable, List, Optional

from config import SCAN_INTERVAL_SECONDS
from detection.engine import detection_engine
from logging_config import (
    CATEGORY_LIFECYCLE,
    CATEGORY_MONITOR,
    log_security_event,
)


class MonitoringState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


class MonitoringWorker:
    """
    Manages the lifecycle of continuous defensive monitoring.
    Ensures zero duplicate worker threads and reliable termination.
    """

    def __init__(self, interval_seconds: float = SCAN_INTERVAL_SECONDS):
        self._interval = interval_seconds
        self._state = MonitoringState.STOPPED
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._cycle_count = 0
        self._last_scan_timestamp: Optional[float] = None
        self._state_change_listeners: List[Callable[[MonitoringState], None]] = []

    @property
    def state(self) -> MonitoringState:
        with self._lock:
            return self._state

    def is_running(self) -> bool:
        with self._lock:
            return self._state == MonitoringState.RUNNING and self._thread is not None and self._thread.is_alive()

    def add_state_listener(self, listener: Callable[[MonitoringState], None]):
        with self._lock:
            self._state_change_listeners.append(listener)

    def _notify_state_change(self, new_state: MonitoringState):
        for listener in self._state_change_listeners:
            try:
                listener(new_state)
            except Exception:
                pass

    def start_monitoring(self) -> bool:
        """
        Starts the background monitoring loop.
        Guards against duplicate worker threads.
        """
        with self._lock:
            if self._state in (MonitoringState.RUNNING, MonitoringState.STARTING) and self._thread and self._thread.is_alive():
                log_security_event(
                    category=CATEGORY_MONITOR,
                    action="START_IGNORED_ALREADY_RUNNING",
                    severity="INFO",
                    details={"cycle_count": self._cycle_count},
                    success=True,
                )
                return False

            self._stop_event.clear()
            self._state = MonitoringState.STARTING
            self._thread = threading.Thread(
                target=self._monitoring_loop,
                name="KeySentinel-MonitorWorker",
                daemon=True,
            )
            self._thread.start()

        log_security_event(
            category=CATEGORY_MONITOR,
            action="MONITORING_ENGINE_STARTED",
            severity="INFO",
            details={"scan_interval": self._interval},
            success=True,
        )
        return True

    def stop_monitoring(self, timeout: float = 5.0) -> bool:
        """
        Gracefully requests the monitoring worker thread to stop.
        Waits for thread termination.
        """
        with self._lock:
            if self._state == MonitoringState.STOPPED:
                return True
            self._state = MonitoringState.STOPPING

        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        with self._lock:
            self._state = MonitoringState.STOPPED
            self._notify_state_change(MonitoringState.STOPPED)

        log_security_event(
            category=CATEGORY_MONITOR,
            action="MONITORING_ENGINE_STOPPED",
            severity="INFO",
            details={"total_cycles_completed": self._cycle_count},
            success=True,
        )
        return True

    def _monitoring_loop(self):
        """Internal execution loop of the background scanner."""
        with self._lock:
            self._state = MonitoringState.RUNNING
            self._notify_state_change(MonitoringState.RUNNING)

        while not self._stop_event.is_set():
            try:
                # Perform inspection cycle
                detection_engine.scan_now()
                self._cycle_count += 1
                self._last_scan_timestamp = time.time()
            except Exception as e:
                log_security_event(
                    category=CATEGORY_MONITOR,
                    action="MONITORING_CYCLE_EXCEPTION",
                    severity="ERROR",
                    details={"error": str(e), "cycle": self._cycle_count},
                    success=False,
                )

            # Wait for interval or stop event
            if self._stop_event.wait(timeout=self._interval):
                break

        with self._lock:
            self._state = MonitoringState.STOPPED


# Global singleton instance
monitor_worker = MonitoringWorker()
