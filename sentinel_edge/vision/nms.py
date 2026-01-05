"""
Non-Maximum Suppression (NMS) for perimeter intrusion threat candidate reduction.
"""
from typing import List
from .bbox import BoundingBox, compute_iou

def apply_nms(boxes: List[BoundingBox], iou_threshold: float = 0.45, min_confidence: float = 0.5) -> List[BoundingBox]:
    """Filters duplicate detections using greedy NMS."""
    filtered = [b for b in boxes if b.confidence >= min_confidence]
    filtered.sort(key=lambda b: b.confidence, reverse=True)
    kept: List[BoundingBox] = []

    while filtered:
        current = filtered.pop(0)
        kept.append(current)
        filtered = [b for b in filtered if compute_iou(current, b) < iou_threshold]

    return kept

def fast_filter_by_class(boxes: List[BoundingBox], target_class: int) -> List[BoundingBox]:
    """Filters detection candidates by target tactical class ID."""
    return [b for b in boxes if b.class_id == target_class]
