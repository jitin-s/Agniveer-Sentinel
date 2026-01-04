"""Unit tests for Geofence Polygon and coordinates."""
import unittest
from sentinel_edge.telemetry.geofence import GeoCoordinate, GeofencePolygon

class TestGeofence(unittest.TestCase):
    def setUp(self):
        self.coords = [
            GeoCoordinate(32.7266, 74.8570),
            GeoCoordinate(32.7278, 74.8582),
            GeoCoordinate(32.7269, 74.8595),
            GeoCoordinate(32.7258, 74.8581)
        ]
        self.polygon = GeofencePolygon("TEST-SEC", self.coords)

    def test_coordinate_validation(self):
        with self.assertRaises(ValueError):
            GeoCoordinate(95.0, 74.0)

    def test_point_inside_polygon(self):
        inside_pt = GeoCoordinate(32.7268, 74.8582)
        self.assertTrue(self.polygon.contains_point(inside_pt))

    def test_point_outside_polygon(self):
        outside_pt = GeoCoordinate(32.7300, 74.8600)
        self.assertFalse(self.polygon.contains_point(outside_pt))

    def test_vertex_proximity(self):
        v0 = self.coords[0]
        self.assertTrue(self.polygon.is_vertex(v0, tolerance_m=1.0))

if __name__ == "__main__":
    unittest.main()
