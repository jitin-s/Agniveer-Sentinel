"""Unit tests for tactical alert prioritization and mesh serialization."""
import unittest
from sentinel_edge.alert.dispatcher import AlertPriority, TacticalAlert, AlertQueue

class TestAlertQueue(unittest.TestCase):
    def test_priority_ordering(self):
        q = AlertQueue()
        low = TacticalAlert("ALT-01", AlertPriority.LOW, "SEC-1", "Low battery")
        crit = TacticalAlert("ALT-02", AlertPriority.CRITICAL, "SEC-1", "Breach detected")
        med = TacticalAlert("ALT-03", AlertPriority.MEDIUM, "SEC-1", "Foliage noise")

        q.push(low)
        q.push(crit)
        q.push(med)

        self.assertEqual(q.pop().alert_id, "ALT-02")
        self.assertEqual(q.pop().alert_id, "ALT-03")
        self.assertEqual(q.pop().alert_id, "ALT-01")

    def test_mesh_serialization(self):
        crit = TacticalAlert("ALT-10", AlertPriority.CRITICAL, "ALPHA", "Hostile vehicle")
        raw = crit.to_mesh_payload()
        self.assertIn(b"ALPHA", raw)
        self.assertIn(b'"pri":1', raw)

    def test_queue_overflow(self):
        q = AlertQueue(max_capacity=2)
        q.push(TacticalAlert("A1", AlertPriority.LOW, "S1", "test"))
        q.push(TacticalAlert("A2", AlertPriority.LOW, "S1", "test"))
        q.push(TacticalAlert("A3", AlertPriority.CRITICAL, "S1", "test"))
        self.assertEqual(q.size(), 2)
        self.assertEqual(q.dropped_count(), 1)

    def test_schema_validation(self):
        crit = TacticalAlert("T1", AlertPriority.CRITICAL, "A", "Test")
        self.assertTrue(TacticalAlert.validate_payload(crit.to_mesh_payload()))

if __name__ == "__main__":
    unittest.main()
