"""
KeySentinel Tests — Configuration Integrity & Access Control
Tests scenarios 6 and 7.
"""

import json
import os
import unittest
from pathlib import Path
from config import PROTECTED_CONFIG_FILE
from security.protection import SecurityProtector


class TestIntegrityAndProtection(unittest.TestCase):

    def setUp(self):
        self.protector = SecurityProtector()

    def test_scenario_6_unauthorized_config_changes_detected(self):
        """Scenario 6: Unauthorized configuration modification fails integrity check and triggers alert."""
        # Establish baseline
        self.protector.update_policy_baseline()
        ok_initial, _, _ = self.protector.check_configuration_integrity()
        self.assertTrue(ok_initial, "Baseline configuration should verify as intact")

        # Simulate tampering by writing modified content
        original_bytes = PROTECTED_CONFIG_FILE.read_bytes()
        try:
            with open(PROTECTED_CONFIG_FILE, "a", encoding="utf-8") as f:
                f.write("\n// UNAUTHORIZED_MALICIOUS_MODIFICATION")

            # Check integrity again
            ok_after_tamper, msg, details = self.protector.check_configuration_integrity()
            self.assertFalse(ok_after_tamper, "Tampered config file must fail integrity check")
            self.assertIn("failed", msg.lower())
            self.assertNotEqual(details.get("expected_hash"), details.get("detected_hash"))
        finally:
            # Restore original content
            PROTECTED_CONFIG_FILE.write_bytes(original_bytes)
            self.protector.update_policy_baseline()

    def test_scenario_7_insufficient_privileges_produce_clear_warnings(self):
        """Scenario 7: Insufficient privileges produce clear notifications without crashing."""
        hardening_results = self.protector.harden_environment()
        self.assertIn("is_admin", hardening_results)

        # If not admin, verify warning message is present and informative
        if not hardening_results["is_admin"]:
            self.assertIn("warning", hardening_results)
            self.assertIn("Administrator", hardening_results["warning"])


if __name__ == "__main__":
    unittest.main()
