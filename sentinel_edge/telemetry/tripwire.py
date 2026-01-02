"""
Tripwire trigger logic with false-positive debounce windows.
Prevents false intrusion alarms caused by environmental vibrations or foliage movement.
"""
import time
from typing import Dict, List, Optional

class TripwireDebounceFilter:
    """
    Debounces tripwire triggers by requiring multiple consecutive activations
    within a sliding time window.
    """
    def __init__(self, window_seconds: float = 1.5, trigger_threshold: int = 3):
        self.window_seconds = window_seconds
        self.trigger_threshold = trigger_threshold
        self._history: Dict[str, List[float]] = {}

    def record_pulse(self, tripwire_id: str, timestamp: Optional[float] = None) -> bool:
        """Records a tripwire beam interruption. Returns True if confirmed alarm."""
        now = timestamp if timestamp is not None else time.time()
        if tripwire_id not in self._history:
            self._history[tripwire_id] = []

        pulses = self._history[tripwire_id]
        pulses.append(now)
        cutoff = now - self.window_seconds
        self._history[tripwire_id] = [t for t in pulses if t >= cutoff]

        if len(self._history[tripwire_id]) >= self.trigger_threshold:
            self._history[tripwire_id].clear()
            return True
        return False

    def get_active_sensors(self) -> List[str]:
        """Returns list of sensor IDs currently holding pulse history."""
        return [k for k, v in self._history.items() if len(v) > 0]

    def reset_sensor(self, tripwire_id: str):
        """Manually clears debounce pulse history for a sensor."""
        if tripwire_id in self._history:
            self._history[tripwire_id].clear()

class MultiBeamTripwireArray:
    """Manages an array of optical tripwire sensors."""
    def __init__(self, sensors: List[str]):
        self.sensors = sensors
        self.filter = TripwireDebounceFilter()
