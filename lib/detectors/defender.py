"""Windows Defender detector implementation."""

import os
import subprocess
import time
from datetime import datetime, timedelta
from typing import Optional, List
import re

from .base import Detector, DetectionResult


class DefenderDetector(Detector):
    """Windows Defender detection checker.
    
    Uses Windows Event Log and MpCmdRun to check for detections.
    """
    
    def _setup(self) -> None:
        """Initialize Defender detector."""
        self.enabled = self.config.get('enabled', True)
        self.check_interval = self.config.get('check_interval', 5)
        
        # MpCmdRun path (Windows Defender command-line tool)
        self.mpcmdrun_path = self._find_mpcmdrun()
    
    def _find_mpcmdrun(self) -> Optional[str]:
        """Find MpCmdRun.exe path."""
        possible_paths = [
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
        ]
        
        for path in possible_paths:
            if '*' in path:
                # Glob pattern - find latest version
                import glob
                matches = glob.glob(path)
                if matches:
                    # Sort by version (assuming folder names are versions)
                    matches.sort(reverse=True)
                    return matches[0]
            elif os.path.exists(path):
                return path
        
        return None
    
    def is_available(self) -> bool:
        """Check if Windows Defender is available."""
        if not self.enabled:
            return False
        
        # Check if running on Windows
        if os.name != 'nt':
            return False
        
        # Check if Defender is running
        try:
            result = subprocess.run(
                ['sc', 'query', 'WinDefend'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return 'RUNNING' in result.stdout
        except Exception:
            return False
    
    def check_detection(
        self,
        process_name: Optional[str] = None,
        file_path: Optional[str] = None,
        time_window_seconds: int = 60,
        **kwargs  # 追加
    ) -> List[DetectionResult]:
        """Check Windows Defender for detections."""
        
        if not self.is_available():
            return []
        
        results = []
        
        # Check Windows Event Log for Defender events
        event_results = self._check_event_log(
            process_name=process_name,
            file_path=file_path,
            time_window_seconds=time_window_seconds
        )
        results.extend(event_results)
        
        # Check threat history via PowerShell
        threat_results = self._check_threat_history(
            file_path=file_path,
            time_window_seconds=time_window_seconds
        )
        results.extend(threat_results)
        
        return results
    
    def _check_event_log(
        self,
        process_name: Optional[str],
        file_path: Optional[str],
        time_window_seconds: int
    ) -> List[DetectionResult]:
        """Check Windows Event Log for Defender events."""
        
        results = []
        
        # PowerShell command to get Defender events
        ps_script = f'''
$startTime = (Get-Date).AddSeconds(-{time_window_seconds})
$events = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction SilentlyContinue | 
    Where-Object {{ $_.TimeCreated -ge $startTime -and $_.Id -in @(1006, 1007, 1008, 1009, 1116, 1117) }}
    
foreach ($event in $events) {{
    $xml = [xml]$event.ToXml()
    $data = @{{
        TimeCreated = $event.TimeCreated.ToString("o")
        EventId = $event.Id
        Message = $event.Message
        ThreatName = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq "Threat Name" }})."#text"
        Path = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq "Path" }})."#text"
        ProcessName = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq "Process Name" }})."#text"
        Action = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq "Action Name" }})."#text"
        Severity = ($xml.Event.EventData.Data | Where-Object {{ $_.Name -eq "Severity Name" }})."#text"
    }}
    $data | ConvertTo-Json -Compress
}}
'''
        
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout.strip():
                import json
                # Parse each JSON line
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        
                        # Filter by process name or file path if specified
                        if process_name and process_name.lower() not in str(data.get('ProcessName', '')).lower():
                            continue
                        if file_path and file_path.lower() not in str(data.get('Path', '')).lower():
                            continue
                        
                        detection = DetectionResult(
                            detected=True,
                            detector_name="defender",
                            rule_name=data.get('ThreatName', 'Unknown Threat'),
                            description=data.get('Message', '')[:500],
                            severity=data.get('Severity', 'Unknown'),
                            process_name=data.get('ProcessName'),
                            file_path=data.get('Path'),
                            details={
                                'event_id': data.get('EventId'),
                                'action': data.get('Action'),
                                'time_created': data.get('TimeCreated')
                            },
                            raw_alert=json.dumps(data)
                        )
                        results.append(detection)
                        
                    except json.JSONDecodeError:
                        continue
                        
        except subprocess.TimeoutExpired:
            print("Warning: Event log query timed out")
        except Exception as e:
            print(f"Error checking event log: {e}")
        
        return results
    
    def _check_threat_history(
        self,
        file_path: Optional[str],
        time_window_seconds: int
    ) -> List[DetectionResult]:
        """Check Defender threat history via PowerShell."""
        
        results = []
        
        ps_script = f'''
$startTime = (Get-Date).AddSeconds(-{time_window_seconds})
Get-MpThreatDetection | 
    Where-Object {{ $_.InitialDetectionTime -ge $startTime }} |
    Select-Object ThreatID, InitialDetectionTime, Resources, ActionSuccess, 
                  @{{Name="ThreatName";Expression={{(Get-MpThreat -ThreatID $_.ThreatID).ThreatName}}}},
                  @{{Name="Severity";Expression={{(Get-MpThreat -ThreatID $_.ThreatID).SeverityID}}}} |
    ConvertTo-Json
'''
        
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                
                # Handle single result vs array
                if isinstance(data, dict):
                    data = [data]
                
                for threat in data:
                    # Filter by file path if specified
                    resources = threat.get('Resources', [])
                    if file_path:
                        if not any(file_path.lower() in str(r).lower() for r in resources):
                            continue
                    
                    severity_map = {1: 'Low', 2: 'Medium', 4: 'High', 5: 'Severe'}
                    severity_id = threat.get('Severity', 0)
                    
                    detection = DetectionResult(
                        detected=True,
                        detector_name="defender",
                        rule_name=threat.get('ThreatName', 'Unknown'),
                        severity=severity_map.get(severity_id, 'Unknown'),
                        file_path=resources[0] if resources else None,
                        details={
                            'threat_id': threat.get('ThreatID'),
                            'action_success': threat.get('ActionSuccess'),
                            'resources': resources
                        },
                        raw_alert=json.dumps(threat, default=str)
                    )
                    results.append(detection)
                    
        except subprocess.TimeoutExpired:
            print("Warning: Threat history query timed out")
        except json.JSONDecodeError:
            pass  # No threats found
        except Exception as e:
            print(f"Error checking threat history: {e}")
        
        return results
    
    def scan_file(self, file_path: str) -> DetectionResult:
        """Actively scan a file with Windows Defender.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            DetectionResult indicating if the file was detected
        """
        if not self.mpcmdrun_path or not os.path.exists(file_path):
            return DetectionResult(
                detected=False,
                detector_name="defender",
                details={'error': 'MpCmdRun not found or file does not exist'}
            )
        
        try:
            result = subprocess.run(
                [self.mpcmdrun_path, '-Scan', '-ScanType', '3', '-File', file_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # MpCmdRun returns 2 if threat found
            if result.returncode == 2:
                # Parse threat details from output
                threat_name = "Unknown"
                match = re.search(r'Threat\s+:\s+(.+)', result.stdout)
                if match:
                    threat_name = match.group(1).strip()
                
                return DetectionResult(
                    detected=True,
                    detector_name="defender",
                    rule_name=threat_name,
                    description="File detected by Windows Defender scan",
                    file_path=file_path,
                    raw_alert=result.stdout
                )
            else:
                return DetectionResult(
                    detected=False,
                    detector_name="defender",
                    file_path=file_path,
                    details={'scan_output': result.stdout}
                )
                
        except subprocess.TimeoutExpired:
            return DetectionResult(
                detected=False,
                detector_name="defender",
                details={'error': 'Scan timed out'}
            )
        except Exception as e:
            return DetectionResult(
                detected=False,
                detector_name="defender",
                details={'error': str(e)}
            )
