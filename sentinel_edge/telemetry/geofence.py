"""
Perimeter geofencing and geospatial boundary coordinate validation.
"""
import math
from typing import List, Tuple, Optional

class GeoCoordinate:
    """Represents a high-precision geographic coordinate (WGS84)."""
    def __init__(self, latitude: float, longitude: float, altitude_m: float = 0.0):
        if not (-90.0 <= latitude <= 90.0):
            raise ValueError(f"Latitude out of bounds: {latitude}")
        if not (-180.0 <= longitude <= 180.0):
            raise ValueError(f"Longitude out of bounds: {longitude}")
        self.lat = float(latitude)
        self.lon = float(longitude)
        self.alt = float(altitude_m)

    def to_tuple(self) -> Tuple[float, float]:
        return (self.lat, self.lon)

    def __repr__(self) -> str:
        return f"GeoCoordinate(lat={self.lat:.6f}, lon={self.lon:.6f}, alt={self.alt:.1f}m)"

class GeofencePolygon:
    """Perimeter boundary polygon with ray-casting point-in-polygon checks."""
    def __init__(self, sector_id: str, vertices: List[GeoCoordinate], description: str = ""):
        if len(vertices) < 3:
            raise ValueError("Geofence polygon requires at least 3 vertices.")
        self.sector_id = sector_id
        self.vertices = vertices
        self.description = description

    def contains_point(self, point: GeoCoordinate) -> bool:
        x, y = point.lon, point.lat
        inside = False
        n = len(self.vertices)
        p1x, p1y = self.vertices[0].lon, self.vertices[0].lat
        for i in range(n + 1):
            p2x, p2y = self.vertices[i % n].lon, self.vertices[i % n].lat
            if min(p1y, p2y) < y <= max(p1y, p2y):
                if x <= max(p1x, p2x):
                    if p1y != p2y:
                        x_inters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    if p1x == p2x or x <= x_inters:
                        inside = not inside
            p1x, p1y = p2x, p2y
        return inside

    @staticmethod
    def haversine_distance_meters(coord1: GeoCoordinate, coord2: GeoCoordinate) -> float:
        """Computes great-circle surface distance between two coordinates in meters."""
        R = 6371000.0
        phi1 = math.radians(coord1.lat)
        phi2 = math.radians(coord2.lat)
        delta_phi = math.radians(coord2.lat - coord1.lat)
        delta_lambda = math.radians(coord2.lon - coord1.lon)
        a = (math.sin(delta_phi / 2.0) ** 2 +
             math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2)
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
        return R * c

    def distance_to_perimeter(self, point: GeoCoordinate) -> float:
        """Returns distance to the nearest vertex boundary."""
        return min(self.haversine_distance_meters(point, v) for v in self.vertices)

    def compute_bounding_box(self) -> Tuple[float, float, float, float]:
        """Calculates (min_lat, min_lon, max_lat, max_lon) bounding box for fast indexing."""
        lats = [v.lat for v in self.vertices]
        lons = [v.lon for v in self.vertices]
        return (min(lats), min(lons), max(lats), max(lons))

    def fast_bbox_check(self, point: GeoCoordinate) -> bool:
        """Sub-millisecond bounding box containment check before ray-casting."""
        min_lat, min_lon, max_lat, max_lon = self.compute_bounding_box()
        return (min_lat <= point.lat <= max_lat) and (min_lon <= point.lon <= max_lon)

    def is_vertex(self, point: GeoCoordinate, tolerance_m: float = 0.5) -> bool:
        """Tolerance proximity check for corner vertices."""
        return any(self.haversine_distance_meters(point, v) <= tolerance_m for v in self.vertices)

    def validate_vertices_distinct(self) -> bool:
        """Ensures all sector boundary vertices are non-duplicate."""
        pts = set(v.to_tuple() for v in self.vertices)
        return len(pts) == len(self.vertices)
