"""Base class for Detection Systems."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


@dataclass
class DetectionResult:
    """Result of detection check."""
    detected: bool
    detector_name: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Detection details
    rule_name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    
    # Process information
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    file_path: Optional[str] = None
    
    # Additional data
    details: Dict[str, Any] = field(default_factory=dict)
    raw_alert: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for AI analysis."""
        return {
            'detected': self.detected,
            'detector': self.detector_name,
            'timestamp': self.timestamp.isoformat(),
            'rule_name': self.rule_name,
            'description': self.description,
            'severity': self.severity,
            'process_name': self.process_name,
            'process_id': self.process_id,
            'file_path': self.file_path,
            'details': self.details,
            'raw_alert': self.raw_alert
        }


class Detector(ABC):
    """Abstract base class for detection systems.
    
    To add a new detector:
    1. Create a new file (e.g., crowdstrike.py)
    2. Inherit from Detector
    3. Implement all abstract methods
    4. Register in __init__.py's get_detector()
    """
    
    def __init__(self, config: dict):
        """Initialize detector with configuration.
        
        Args:
            config: Detector-specific configuration from config.yaml
        """
        self.config = config
        self.name = self.__class__.__name__.replace('Detector', '').lower()
        self._setup()
    
    @abstractmethod
    def _setup(self) -> None:
        """Setup detector (API client initialization, etc.)."""
        pass
    
    @abstractmethod
    def check_detection(
        self,
        process_name: Optional[str] = None,
        file_path: Optional[str] = None,
        time_window_seconds: int = 60,
        **kwargs  # 追加パラメータを許可
    ) -> List[DetectionResult]:
        """Check for detections related to the executed file/process.
        
        Args:
            process_name: Name of the process to check
            file_path: Path to the executed file
            time_window_seconds: How far back to look for detections
            **kwargs: Additional detector-specific parameters
            
        Returns:
            List of DetectionResult objects (empty if no detections)
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the detector is available and properly configured.
        
        Returns:
            True if detector can be used, False otherwise
        """
        pass
    
    def get_name(self) -> str:
        """Get detector name."""
        return self.name
    
    def merge_detection_results(self, results: List[DetectionResult]) -> DetectionResult:
        """Merge multiple detections into a single result.
        
        Args:
            results: List of detection results
            
        Returns:
            Merged DetectionResult
        """
        if not results:
            return DetectionResult(
                detected=False,
                detector_name=self.name
            )
        
        if len(results) == 1:
            return results[0]
        
        # Merge multiple detections
        merged_details = {}
        all_rules = []
        all_descriptions = []
        highest_severity = None
        severity_order = ['low', 'medium', 'high', 'critical']
        
        for r in results:
            if r.rule_name:
                all_rules.append(r.rule_name)
            if r.description:
                all_descriptions.append(r.description)
            if r.severity:
                if highest_severity is None:
                    highest_severity = r.severity
                elif r.severity in severity_order and highest_severity in severity_order:
                    if severity_order.index(r.severity) > severity_order.index(highest_severity):
                        highest_severity = r.severity
            merged_details.update(r.details)
        
        return DetectionResult(
            detected=True,
            detector_name=self.name,
            rule_name=" | ".join(set(all_rules)) if all_rules else None,
            description=" | ".join(set(all_descriptions)) if all_descriptions else None,
            severity=highest_severity,
            process_name=results[0].process_name,
            process_id=results[0].process_id,
            file_path=results[0].file_path,
            details=merged_details,
            raw_alert=results[0].raw_alert
        )
