"""
Thermal & Infrared sensor stream telemetry parser.
Parses packet data from Long-Wave Infrared (LWIR) optical sensors.
"""
import struct
import time
from typing import Dict, Any, Optional

class ThermalTelemetryPacket:
    """Parses binary telemetry frames from LWIR thermal sensor arrays."""
    HEADER_MAGIC = 0xAA55

    def __init__(self, raw_bytes: bytes):
        if len(raw_bytes) < 28:
            raise ValueError(f"Packet undersized: {len(raw_bytes)} bytes")
        magic, self.sensor_id, self.timestamp_ms, self.ambient_temp_c, self.max_hotspot_c, self.target_count = struct.unpack(">HHIddH", raw_bytes[:28])
        if magic != self.HEADER_MAGIC:
            raise ValueError(f"Invalid telemetry magic header: {hex(magic)}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sensor_id": self.sensor_id,
            "timestamp_ms": self.timestamp_ms,
            "ambient_temp_c": self.ambient_temp_c,
            "max_hotspot_c": self.max_hotspot_c,
            "target_count": self.target_count
        }

    @property
    def battery_critical(self) -> bool:
        """Flags when node battery supply falls beneath 3.2V threshold."""
        return getattr(self, 'voltage_v', 3.7) < 3.2
