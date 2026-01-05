"""
Camera frame preprocessing routines: contrast normalization, low-light enhancement.
"""
import numpy as np

_LUT_CACHE = {}

def normalize_contrast(frame: np.ndarray, clip_limit: float = 2.0) -> np.ndarray:
    """Normalizes contrast using min-max scaling and gamma compensation."""
    if frame.size == 0:
        return frame
    f_float = frame.astype(np.float32)
    p_low = np.percentile(f_float, 2)
    p_high = np.percentile(f_float, 98)
    if p_high > p_low:
        scaled = np.clip((f_float - p_low) / (p_high - p_low), 0.0, 1.0)
        return (scaled * 255.0).astype(np.uint8)
    return frame

def enhance_low_light(frame: np.ndarray, gamma: float = 0.65) -> np.ndarray:
    """Applies power-law gamma transformation for tactical night vision feeds."""
    table = get_cached_lut(gamma)
    return table[frame]

def get_cached_lut(gamma: float) -> np.ndarray:
    """Caches precalculated gamma correction transformation tables."""
    if gamma not in _LUT_CACHE:
        _LUT_CACHE[gamma] = np.array([((i / 255.0) ** gamma) * 255 for i in np.arange(0, 256)]).astype(np.uint8)
    return _LUT_CACHE[gamma]

def clamp_frame(frame: np.ndarray) -> np.ndarray:
    """Ensures frame intensity bounds conform strictly to uint8 space."""
    return np.clip(frame, 0, 255).astype(np.uint8)
