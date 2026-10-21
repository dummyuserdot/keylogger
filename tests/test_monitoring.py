"""
KeySentinel Tests — Background Monitoring Lifecycle
Tests scenarios 4 and 9.
"""

import threading
import time
import unittest
from monitoring.worker import MonitoringState, MonitoringWorker


class TestMonitoringWorker(unittest.TestCase):

    def test_scenario_4_start_and_stop_cleanly_no_lingering_threads(self):
        """Scenario 4: Monitoring starts and stops cleanly without leaving background threads running."""
        worker = MonitoringWorker(interval_seconds=0.2)

        self.assertEqual(worker.state, MonitoringState.STOPPED)
        started = worker.start_monitoring()
        self.assertTrue(started)

        # Allow worker loop to spin
        time.sleep(0.4)
        self.assertTrue(worker.is_running())

        # Stop monitoring
        stopped = worker.stop_monitoring(timeout=2.0)
        self.assertTrue(stopped)
        self.assertEqual(worker.state, MonitoringState.STOPPED)
        self.assertFalse(worker.is_running())

        # Verify thread is dead
        if worker._thread:
            self.assertFalse(worker._thread.is_alive())

    def test_scenario_9_prevents_duplicate_workers_and_non_blocking(self):
        """Scenario 9: Starting an already running worker is safely debounced/ignored."""
        worker = MonitoringWorker(interval_seconds=0.5)
        worker.start_monitoring()

        # Second start call should return False (ignored)
        second_start = worker.start_monitoring()
        self.assertFalse(second_start)

        worker.stop_monitoring()


if __name__ == "__main__":
    unittest.main()
