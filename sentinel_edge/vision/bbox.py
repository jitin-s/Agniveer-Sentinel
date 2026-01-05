"""
Bounding Box utilities, spatial intersections, and Intersection-over-Union (IoU).
"""
from typing import Tuple, List, Dict, Any

class BoundingBox:
    """Represents a 2D bounding box (xmin, ymin, xmax, ymax) with confidence and class label."""
    def __init__(self, xmin: float, ymin: float, xmax: float, ymax: float, confidence: float, class_id: int, label: str = ""):
        self.xmin = float(xmin)
        self.ymin = float(ymin)
        self.xmax = float(xmax)
        self.ymax = float(ymax)
        self.confidence = float(confidence)
        self.class_id = int(class_id)
        self.label = label

    @property
    def area(self) -> float:
        w = max(0.0, self.xmax - self.xmin)
        h = max(0.0, self.ymax - self.ymin)
        return w * h

    def to_dict(self) -> Dict[str, Any]:
        return {
            "box": [self.xmin, self.ymin, self.xmax, self.ymax],
            "confidence": round(self.confidence, 4),
            "class_id": self.class_id,
            "label": self.label
        }

    def scale(self, sx: float, sy: float) -> "BoundingBox":
        """Scales bounding box coordinates by horizontal and vertical ratios."""
        return BoundingBox(self.xmin * sx, self.ymin * sy, self.xmax * sx, self.ymax * sy, self.confidence, self.class_id, self.label)

def compute_iou(box_a: BoundingBox, box_b: BoundingBox) -> float:
    """Computes Intersection-over-Union (IoU) between two bounding boxes."""
    x_left = max(box_a.xmin, box_b.xmin)
    y_top = max(box_a.ymin, box_b.ymin)
    x_right = min(box_a.xmax, box_b.xmax)
    y_bottom = min(box_a.ymax, box_b.ymax)

    if x_right < x_left or y_bottom < y_top:
        return 0.0

    intersection_area = (x_right - x_left) * (y_bottom - y_top)
    union_area = box_a.area + box_b.area - intersection_area
    if union_area <= 0.0:
        return 0.0
    return intersection_area / union_area
