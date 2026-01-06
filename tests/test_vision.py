"""Unit tests for bounding boxes and frame preprocessing."""
import unittest
import numpy as np
from sentinel_edge.vision.bbox import BoundingBox, compute_iou
from sentinel_edge.vision.nms import apply_nms
from sentinel_edge.vision.preprocessor import normalize_contrast, enhance_low_light, get_cached_lut

class TestVision(unittest.TestCase):
    def test_iou_identical(self):
        b1 = BoundingBox(10, 10, 50, 50, 0.9, 1, "person")
        b2 = BoundingBox(10, 10, 50, 50, 0.85, 1, "person")
        self.assertAlmostEqual(compute_iou(b1, b2), 1.0, places=3)

    def test_iou_disjoint(self):
        b1 = BoundingBox(0, 0, 10, 10, 0.9, 1, "vehicle")
        b2 = BoundingBox(20, 20, 30, 30, 0.8, 1, "vehicle")
        self.assertEqual(compute_iou(b1, b2), 0.0)

    def test_nms_filtering(self):
        boxes = [
            BoundingBox(10, 10, 50, 50, 0.95, 1, "target"),
            BoundingBox(12, 12, 48, 48, 0.80, 1, "target"),
            BoundingBox(100, 100, 150, 150, 0.90, 2, "drone")
        ]
        kept = apply_nms(boxes, iou_threshold=0.5)
        self.assertEqual(len(kept), 2)

    def test_low_light_transform(self):
        frame = np.ones((100, 100), dtype=np.uint8) * 30
        enhanced = enhance_low_light(frame, gamma=0.5)
        self.assertGreater(enhanced[0, 0], frame[0, 0])

    def test_lut_caching(self):
        lut1 = get_cached_lut(0.65)
        lut2 = get_cached_lut(0.65)
        self.assertIs(lut1, lut2)

if __name__ == "__main__":
    unittest.main()
