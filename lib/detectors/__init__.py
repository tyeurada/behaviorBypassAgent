"""Detector module for EDR/AV detection checking."""

from .base import Detector, DetectionResult
from .elastic import ElasticDetector
from .defender import DefenderDetector

__all__ = ['Detector', 'DetectionResult', 'ElasticDetector', 'DefenderDetector', 'get_detector', 'get_all_detectors']


def get_detector(detector_name: str, config: dict) -> Detector:
    """Factory function to get detector instance.
    
    Args:
        detector_name: Name of the detector (elastic, defender)
        config: Detector-specific configuration
        
    Returns:
        Detector instance
    """
    detectors = {
        'elastic': ElasticDetector,
        'defender': DefenderDetector,
        # 将来の拡張用
        # 'crowdstrike': CrowdStrikeDetector,
        # 'sentinelone': SentinelOneDetector,
    }
    
    if detector_name not in detectors:
        raise ValueError(f"Unknown detector: {detector_name}. Available: {list(detectors.keys())}")
    
    return detectors[detector_name](config)


def get_all_detectors(config: dict) -> list:
    """Get all enabled detectors.
    
    Args:
        config: Full detectors configuration
        
    Returns:
        List of enabled Detector instances
    """
    enabled = config.get('enabled', [])
    detectors = []
    
    for name in enabled:
        if name in config:
            try:
                detector = get_detector(name, config[name])
                detectors.append(detector)
            except Exception as e:
                print(f"Warning: Failed to initialize {name} detector: {e}")
    
    return detectors
