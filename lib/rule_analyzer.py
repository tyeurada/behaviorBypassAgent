"""Behavior Rule Analyzer for Elastic Detection Rules."""

import os
import re
from pathlib import Path
from typing import Optional, Dict, List
import tomli


class BehaviorRule:
    """Represents an Elastic behavior detection rule."""
    
    def __init__(self, file_path: str, data: dict):
        """Initialize behavior rule from TOML data.
        
        Args:
            file_path: Path to the TOML rule file
            data: Parsed TOML data
        """
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        
        rule = data.get('rule', {})
        self.rule_id = rule.get('id', '')
        self.name = rule.get('name', '')
        self.description = rule.get('description', '')
        self.query = rule.get('query', '')
        self.version = rule.get('version', '')
        self.os_list = rule.get('os_list', [])
        self.mitre_attack = rule.get('mitre_attack', [])
        
        # Parse query to extract detection logic
        self.detection_patterns = self._parse_query_patterns()
    
    def _parse_query_patterns(self) -> Dict[str, List[str]]:
        """Extract detection patterns from the query.
        
        Returns:
            Dictionary of pattern types and their values
        """
        patterns = {
            'api_calls': [],
            'file_paths': [],
            'process_names': [],
            'memory_protections': [],
            'behaviors': [],
            'exclusions': []
        }
        
        if not self.query:
            return patterns
        
        query_lower = self.query.lower()
        
        # Extract API calls
        api_pattern = r'[\w\.]+(?:alloc|protect|write|create|load|hook|inject|call|exec|execute|read)\w*'
        api_matches = re.findall(api_pattern, self.query, re.IGNORECASE)
        patterns['api_calls'] = list(set(api_matches))
        
        # Extract file paths
        path_pattern = r'["\']([C-Z]:\\\\[^"\']+)["\']|[\w\.]+\s*:\s*["\']([^"\']*\\\\[^"\']+)["\']'
        path_matches = re.findall(path_pattern, self.query)
        for match_tuple in path_matches:
            for path in match_tuple:
                if path:
                    patterns['file_paths'].append(path)
        
        # Extract process names
        if 'process.name' in self.query or 'process.executable' in self.query:
            name_pattern = r'process\.(?:name|executable)\s*:\s*["\']([^"\']+)["\']'
            name_matches = re.findall(name_pattern, self.query)
            patterns['process_names'].extend(name_matches)
        
        # Extract memory protections
        if 'rwx' in query_lower or 'execute' in query_lower:
            if 'page_execute_readwrite' in query_lower or 'rwx' in query_lower:
                patterns['memory_protections'].append('RWX')
            if 'page_execute_read' in query_lower:
                patterns['memory_protections'].append('RX')
        
        # Extract behavioral patterns
        behavior_keywords = [
            'injection', 'hollowing', 'shellcode', 'unbacked', 'unsigned',
            'suspicious', 'hook', 'syscall', 'heap', 'private memory',
            'code_signature', 'relative_file_creation_time', 'descendant',
            'http', 'download', 'ingress', 'powershell'
        ]
        
        for keyword in behavior_keywords:
            if keyword in query_lower:
                patterns['behaviors'].append(keyword)
        
        # Extract exclusions (patterns to avoid)
        if 'not ' in query_lower:
            not_pattern = r'not\s+(?:process\.)?(?:name|executable|path|command_line)\s*:\s*["\']?([^"\')\s]+)["\']?'
            exclusion_matches = re.findall(not_pattern, self.query, re.IGNORECASE)
            patterns['exclusions'].extend(exclusion_matches)
        
        return patterns
    
    def to_dict(self) -> dict:
        """Convert rule to dictionary format.
        
        Returns:
            Dictionary representation of the rule
        """
        return {
            'file_name': self.file_name,
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'query': self.query,
            'version': self.version,
            'os_list': self.os_list,
            'detection_patterns': self.detection_patterns,
        }


class BehaviorRuleAnalyzer:
    """Analyzer for Elastic behavior detection rules."""
    
    def __init__(self, rules_directory: str = None):
        """Initialize rule analyzer.
        
        Args:
            rules_directory: Path to directory containing TOML rule files
        """
        if rules_directory is None:
            # Default to windowsBehaviorRules in project root
            project_root = Path(__file__).parent.parent
            rules_directory = project_root / 'windowsBehaviorRules'
        
        self.rules_directory = Path(rules_directory)
        self.rules: Dict[str, BehaviorRule] = {}  # By file name
        self.rules_by_name: Dict[str, BehaviorRule] = {}  # By rule name
        self.rules_by_id: Dict[str, BehaviorRule] = {}  # NEW: By rule ID
        
        if self.rules_directory.exists():
            self._load_rules()
    
    def _load_rules(self) -> None:
        """Load all TOML rule files from directory."""
        if not self.rules_directory.exists():
            print(f"Warning: Rules directory not found: {self.rules_directory}")
            return
        
        loaded_count = 0
        for rule_file in self.rules_directory.glob('*.toml'):
            try:
                with open(rule_file, 'rb') as f:
                    data = tomli.load(f)
                    rule = BehaviorRule(str(rule_file), data)
                    
                    # Store by file name
                    self.rules[rule.file_name] = rule
                    
                    # Store by rule name (normalized)
                    if rule.name:
                        normalized_name = rule.name.lower()
                        self.rules_by_name[normalized_name] = rule
                    
                    # NEW: Store by rule ID (primary key for Elastic alerts)
                    if rule.rule_id:
                        self.rules_by_id[rule.rule_id] = rule
                    
                    loaded_count += 1
            except Exception as e:
                print(f"Warning: Failed to load rule {rule_file}: {e}")
        
        print(f"[Rule Analyzer] Loaded {loaded_count} behavior rules from {self.rules_directory}")
        print(f"[Rule Analyzer] Indexed {len(self.rules_by_id)} rules by ID")
    
    def find_rule_by_id(self, rule_id: str) -> Optional[BehaviorRule]:
        """Find a rule by its ID (primary method for Elastic alerts).
        
        Args:
            rule_id: UUID of the rule (e.g., '58b996a5-634c-4205-9ffa-a6f2b8ebc1ad')
            
        Returns:
            BehaviorRule if found, None otherwise
        """
        if not rule_id:
            return None
        
        return self.rules_by_id.get(rule_id)
    
    def find_rule_by_name(self, rule_name: str) -> Optional[BehaviorRule]:
        """Find a rule by its name (case-insensitive).
        
        Args:
            rule_name: Name of the rule to find
            
        Returns:
            BehaviorRule if found, None otherwise
        """
        if not rule_name:
            return None
        
        # Try exact match (case-insensitive)
        normalized = rule_name.lower()
        if normalized in self.rules_by_name:
            return self.rules_by_name[normalized]
        
        # Try fuzzy match - search for rule name containing the query
        for stored_name, rule in self.rules_by_name.items():
            if normalized in stored_name or stored_name in normalized:
                return rule
        
        # Try matching by file name pattern
        # Convert rule name to potential file name
        # e.g., "Ingress Tool Transfer via PowerShell" -> "ingress_tool_transfer_via_powershell"
        file_pattern = re.sub(r'[^\w\s]', '', rule_name.lower())
        file_pattern = re.sub(r'\s+', '_', file_pattern)
        
        for file_name, rule in self.rules.items():
            if file_pattern in file_name.lower():
                return rule
        
        return None
    
    def find_rules_by_keywords(self, keywords: List[str]) -> List[BehaviorRule]:
        """Find rules matching any of the keywords.
        
        Args:
            keywords: List of keywords to search for
            
        Returns:
            List of matching rules
        """
        matching_rules = []
        keywords_lower = [k.lower() for k in keywords]
        
        for rule in self.rules.values():
            # Search in name, description, and query
            searchable = ' '.join([
                rule.name.lower(),
                rule.description.lower(),
                rule.query.lower()
            ])
            
            if any(keyword in searchable for keyword in keywords_lower):
                matching_rules.append(rule)
        
        return matching_rules
    
    def analyze_detection(self, detection_result) -> Optional[Dict]:
        """Analyze a detection result and find matching rule.
        
        Args:
            detection_result: DetectionResult object OR dictionary
            
        Returns:
            Dictionary with rule analysis or None if no rule found
        """
        if not detection_result:
            return None
        
        # Helper to get attribute or dict key
        def get_val(obj, key, default=None):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        target_details = get_val(detection_result, 'details', {})
        target_rule_name = get_val(detection_result, 'rule_name')
        target_description = get_val(detection_result, 'description')
        
        rule = None
        
        # PRIMARY: Try to find by rule ID (most reliable)
        if target_details and 'rule_id' in target_details:
            rule_id = target_details['rule_id']
            rule = self.find_rule_by_id(rule_id)
            if rule:
                print(f"[Rule Analyzer] Match by ID: {rule_id} -> {rule.name}")
        
        # FALLBACK 1: Try to find by rule name
        if not rule and target_rule_name:
            rule = self.find_rule_by_name(target_rule_name)
            if rule:
                print(f"[Rule Analyzer] Match by name: {target_rule_name}")
        
        # FALLBACK 2: Try to find by keywords from the detection
        if not rule:
            keywords = []
            if target_description:
                keywords.extend(target_description.split()[:5])
            if target_rule_name:
                keywords.extend(target_rule_name.split())
            
            if keywords:
                matching_rules = self.find_rules_by_keywords(keywords)
                if matching_rules:
                    rule = matching_rules[0]  # Use best match
                    print(f"[Rule Analyzer] Match by keywords: {', '.join(keywords[:3])}")
        
        if rule:
            return {
                'rule_found': True,
                'rule_id': rule.rule_id,
                'rule_file': rule.file_name,
                'rule_name': rule.name,
                'rule_description': rule.description,
                'detection_query': rule.query,
                'detection_patterns': rule.detection_patterns,
                'full_rule': rule.to_dict()
            }
        
        return {
            'rule_found': False,
            'message': f"Could not find rule file for: {target_rule_name or 'Unknown'}"
        }
    
    def get_all_rules(self) -> List[BehaviorRule]:
        """Get all loaded rules.
        
        Returns:
            List of all behavior rules
        """
        return list(self.rules.values())
    
    def get_rule_statistics(self) -> Dict:
        """Get statistics about loaded rules.
        
        Returns:
            Dictionary with rule statistics
        """
        return {
            'total_rules': len(self.rules),
            'rules_by_os': self._count_by_os(),
            'common_behaviors': self._get_common_behaviors()
        }
    
    def _count_by_os(self) -> Dict[str, int]:
        """Count rules by OS."""
        os_counts = {}
        for rule in self.rules.values():
            for os_name in rule.os_list:
                os_counts[os_name] = os_counts.get(os_name, 0) + 1
        return os_counts
    
    def _get_common_behaviors(self) -> List[str]:
        """Get most common behavioral patterns across all rules."""
        behavior_counts = {}
        for rule in self.rules.values():
            for behavior in rule.detection_patterns.get('behaviors', []):
                behavior_counts[behavior] = behavior_counts.get(behavior, 0) + 1
        
        # Return top 10
        sorted_behaviors = sorted(behavior_counts.items(), key=lambda x: x[1], reverse=True)
        return [behavior for behavior, count in sorted_behaviors[:10]]
