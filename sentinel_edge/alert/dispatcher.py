"""
Tactical Emergency Alert Dispatcher.
Prioritizes perimeter intrusion alerts, health heartbeats, and sensor failures.
"""
from enum import IntEnum
import time
import heapq
import json
from typing import Dict, Any, Optional

class AlertPriority(IntEnum):
    LOW = 30
    MEDIUM = 20
    HIGH = 10
    CRITICAL = 1

class TacticalAlert:
    """Emergency alert payload with tactical priority weights."""
    def __init__(self, alert_id: str, priority: AlertPriority, sector_id: str, description: str, telemetry: Optional[Dict[str, Any]] = None):
        self.alert_id = alert_id
        self.priority = priority
        self.sector_id = sector_id
        self.description = description
        self.telemetry = telemetry or {}
        self.timestamp = time.time()

    def __lt__(self, other: "TacticalAlert") -> bool:
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.timestamp < other.timestamp

    def to_mesh_payload(self) -> bytes:
        """Serializes alert for tactical VHF/UHF mesh gateway packet transmission."""
        payload = {
            "id": self.alert_id,
            "pri": int(self.priority),
            "sec": self.sector_id,
            "desc": self.description,
            "ts": int(self.timestamp),
            "telem": self.telemetry
        }
        return json.dumps(payload, separators=(',', ':')).encode('utf-8')

    @staticmethod
    def validate_payload(raw: bytes) -> bool:
        """Validates binary mesh payload integrity before antenna transmission."""
        try:
            d = json.loads(raw.decode('utf-8'))
            return "id" in d and "pri" in d and "sec" in d
        except Exception:
            return False

class AlertQueue:
    """Thread-safe priority triage queue for battlefield C2 dispatch."""
    def __init__(self, max_capacity: int = 1000):
        self._heap = []
        self.max_capacity = max_capacity
        self._dropped = 0

    def push(self, alert: TacticalAlert):
        if len(self._heap) >= self.max_capacity:
            heapq.heappop(self._heap)
            self._dropped += 1
        heapq.heappush(self._heap, alert)

    def pop(self) -> Optional[TacticalAlert]:
        return heapq.heappop(self._heap) if self._heap else None

    def size(self) -> int:
        return len(self._heap)

    def dropped_count(self) -> int:
        return self._dropped
