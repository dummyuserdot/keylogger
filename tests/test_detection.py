"""
KeySentinel Tests — Keylogger Detection Engine & Resilience
Tests scenarios 5, 8, and anti-false-positive filtering.
"""

import unittest
from config import WH_KEYBOARD_LL
from detection.engine import DetectionEngine
from detection.hook_detector import HookDetector
from detection.process_inspector import ProcessInspector
from detection.rules import ThreatSeverity


class TestDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DetectionEngine()

    def test_scenario_5_suspicious_indicators_generate_alerts(self):
        """Scenario 5: Suspicious process indicators generate alerts with evidence."""
        # Inject simulated low-level keyboard hook
        self.engine.hook_detector.inject_test_hook_signal(
            pid=9999,
            process_name="keylogger_agent.exe",
            hook_type=WH_KEYBOARD_LL,
            module_name="klog_hook.dll",
        )

        threats = self.engine.scan_now()
        flagged = [t for t in threats if t.pid == 9999 or t.process_name == "keylogger_agent.exe"]
        self.assertTrue(len(flagged) > 0, "Expected simulated keylogger to be detected")

        threat = flagged[0]
        self.assertEqual(threat.process_name, "keylogger_agent.exe")
        self.assertIn("Keyboard Hook", threat.indicators[0].title)
        self.assertGreaterEqual(threat.confidence_score, 40)

        # Cleanup
        self.engine.hook_detector.clear_test_hooks()

    def test_scenario_8_handles_inaccessible_processes_and_api_failures(self):
        """Scenario 8: Engine handles inaccessible processes and errors without crashing."""
        inspector = ProcessInspector()

        # Simulated inaccessible / corrupted process info
        broken_proc_1 = {"pid": 4, "name": None, "exe": None, "cmdline": None}
        broken_proc_2 = {"pid": -99, "name": "unknown_svc", "exe": "access_denied"}

        # Running inspection must not raise exception
        ind1 = inspector.inspect_process(broken_proc_1)
        ind2 = inspector.inspect_process(broken_proc_2)

        self.assertIsInstance(ind1, list)
        self.assertIsInstance(ind2, list)

    def test_anti_false_positive_for_legitimate_software(self):
        """Heuristics must distinguish legitimate gaming overlays or utilities from stealth keyloggers."""
        hook_detector = HookDetector()
        hook_detector.inject_test_hook_signal(
            pid=1234,
            process_name="discord.exe",
            hook_type=WH_KEYBOARD_LL,
        )

        indicators = hook_detector.inspect_process_for_keyboard_hooks(
            pid=1234,
            process_name="discord.exe",
            loaded_modules=["user32.dll"],
        )

        self.assertTrue(len(indicators) > 0)
        # Verify severity was downgraded to LOW due to known legitimate software rule
        self.assertEqual(indicators[0].severity, ThreatSeverity.LOW)
        self.assertIn("BENIGN CONTEXT", indicators[0].description)

    def test_suspicious_temp_path_detection(self):
        """Binaries running out of Temp folder trigger high-severity alert."""
        inspector = ProcessInspector()
        suspicious_proc = {
            "pid": 8888,
            "name": "updater.exe",
            "exe": "C:\\Users\\Victim\\AppData\\Local\\Temp\\updater.exe",
            "cmdline": "updater.exe -klog",
        }
        indicators = inspector.inspect_process(suspicious_proc)
        categories = [ind.category.value for ind in indicators]

        self.assertIn("SUSPICIOUS_EXECUTABLE_PATH", categories)
        self.assertIn("ASYNC_KEYSTATE_POLLING", categories)


if __name__ == "__main__":
    unittest.main()
