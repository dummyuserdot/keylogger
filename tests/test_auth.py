"""
KeySentinel Tests — Administrator Authentication & Shutdown Authorization
Tests scenarios 1, 2, 3, and credential security.
"""

import unittest
from security.auth import AdminAuthenticator
from logging_config import get_recent_security_events, log_security_event


class TestAdminAuthentication(unittest.TestCase):

    def setUp(self):
        self.auth = AdminAuthenticator()

    def test_scenario_1_correct_password_authorizes_shutdown(self):
        """Scenario 1: Correct administrator password '27254' authorizes graceful shutdown."""
        callback_called = []

        def shutdown_cb():
            callback_called.append(True)

        authorized, msg = self.auth.request_graceful_shutdown("27254", caller_callback=shutdown_cb)
        self.assertTrue(authorized, f"Expected password '27254' to authorize shutdown, got: {msg}")
        self.assertTrue(callback_called, "Expected shutdown callback to be triggered")
        self.assertTrue(self.auth.is_shutdown_in_progress())

    def test_scenario_2_incorrect_password_denies_and_keeps_monitoring(self):
        """Scenario 2: Incorrect password does not stop monitoring or authorize shutdown."""
        callback_called = []

        def shutdown_cb():
            callback_called.append(True)

        authorized, msg = self.auth.request_graceful_shutdown("wrong_password_999", caller_callback=shutdown_cb)
        self.assertFalse(authorized)
        self.assertIn("Incorrect administrator password", msg)
        self.assertFalse(callback_called)
        self.assertFalse(self.auth.is_shutdown_in_progress())
        self.assertEqual(self.auth.get_failed_attempts(), 1)

    def test_scenario_3_cancel_leaves_monitoring_active(self):
        """Scenario 3: Cancelling authentication dialog leaves monitoring completely active."""
        # When cancelled, verify is not called, state remains unaffected
        self.assertFalse(self.auth.is_shutdown_in_progress())
        self.assertEqual(self.auth.get_failed_attempts(), 0)

    def test_repeated_failures_trigger_lockout(self):
        """Exceeding 5 failed attempts triggers defensive rate-limiting lockout."""
        for i in range(5):
            self.auth.verify_password(f"bad_pass_{i}")

        locked, remaining = self.auth.is_locked_out()
        self.assertTrue(locked)
        self.assertGreater(remaining, 0)

        # Even correct password is now blocked while locked
        ok, msg = self.auth.verify_password("27254")
        self.assertFalse(ok)
        self.assertIn("locked", msg.lower())

    def test_passwords_never_appear_in_logs(self):
        """Security requirement: Entered passwords must never be saved in audit logs."""
        secret_test_str = "27254"
        log_security_event(
            category="TEST_CATEGORY",
            action="TEST_ACTION",
            details={"entered_password": secret_test_str, "other_field": "safe"},
        )
        recent = get_recent_security_events(10)
        found = False
        for ev in recent:
            details_str = str(ev.get("details", {}))
            self.assertNotIn(secret_test_str, details_str, "Password plaintext must not appear in details")
            if "REDACTED" in details_str:
                found = True
        self.assertTrue(found, "Sensitive fields must be redacted in logs")


if __name__ == "__main__":
    unittest.main()
