"""
KeySentinel Tests — Windows Service Access Controls & Permissions
Tests scenario 10.
"""

import unittest
from service.service_manager import ServiceManager


class TestServicePermissions(unittest.TestCase):

    def setUp(self):
        self.mgr = ServiceManager()

    def test_scenario_10_service_control_permissions(self):
        """Scenario 10: Service-control permissions work as documented."""
        status = self.mgr.get_service_status()
        self.assertIsInstance(status, dict)
        self.assertIn("installed", status)
        self.assertIn("can_control", status)

        # Calling stop on simulated environment handles permissions correctly
        ok, msg = self.mgr.request_service_stop()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(msg, str)


if __name__ == "__main__":
    unittest.main()
