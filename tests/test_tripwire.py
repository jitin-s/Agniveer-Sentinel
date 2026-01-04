"""Unit tests for tripwire debounce filters."""
import unittest
from sentinel_edge.telemetry.tripwire import TripwireDebounceFilter

class TestTripwire(unittest.TestCase):
    def test_debounce_suppression(self):
        db = TripwireDebounceFilter(window_seconds=1.0, trigger_threshold=3)
        self.assertFalse(db.record_pulse("BEAM-1", timestamp=10.0))
        self.assertFalse(db.record_pulse("BEAM-1", timestamp=10.2))
        self.assertTrue(db.record_pulse("BEAM-1", timestamp=10.4))

    def test_noise_expiration(self):
        db = TripwireDebounceFilter(window_seconds=1.0, trigger_threshold=3)
        self.assertFalse(db.record_pulse("BEAM-2", timestamp=1.0))
        self.assertFalse(db.record_pulse("BEAM-2", timestamp=2.5))
        self.assertFalse(db.record_pulse("BEAM-2", timestamp=3.0))

if __name__ == "__main__":
    unittest.main()
