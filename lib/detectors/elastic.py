"""Elastic Defend / Elasticsearch detector implementation."""

import os
from datetime import datetime, timedelta
from typing import Optional, List

from elasticsearch import Elasticsearch

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .base import Detector, DetectionResult


class ElasticDetector(Detector):
    """Elastic Defend detector using Elasticsearch API."""
    
    def _setup(self) -> None:
        """Initialize Elasticsearch client."""
        self.host = self.config.get('host', 'localhost')
        self.port = self.config.get('port', 9200)
        self.use_ssl = self.config.get('use_ssl', True)
        self.verify_certs = self.config.get('verify_certs', False)
        self.index_pattern = self.config.get('index_pattern', '.alerts-security.alerts-*, .internal.alerts-security.alerts-*')
        self.debug = self.config.get('debug', True)
        
        # Get API key from environment or config
        # Support both encoded format (single base64 string) and tuple format (id, secret)
        api_key_encoded = os.getenv('ELASTIC_API_KEY') or self.config.get('api_key')
        api_key_id = os.getenv('ELASTIC_API_KEY_ID') or self.config.get('api_key_id')
        api_key_secret = os.getenv('ELASTIC_API_KEY_SECRET') or self.config.get('api_key_secret')
        
        if api_key_encoded:
            # Use encoded format (base64 string)
            self.api_key = api_key_encoded
        elif api_key_id and api_key_secret:
            # Use tuple format (id, secret)
            self.api_key = (api_key_id, api_key_secret)
        else:
            self.api_key = None
        
        # Get username/password from environment or config
        self.username = os.getenv('ELASTIC_USERNAME') or self.config.get('username')
        self.password = os.getenv('ELASTIC_PASSWORD') or self.config.get('password')
        
        # Build connection URL
        scheme = 'https' if self.use_ssl else 'http'
        self.es_url = f"{scheme}://{self.host}:{self.port}"
        
        self.client = None
        self._init_client()
    
    def _init_client(self) -> None:
        """Initialize the Elasticsearch client."""
        # Suppress insecure connection warnings if certificate verification is disabled
        if not self.verify_certs:
            import warnings
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass
            try:
                warnings.filterwarnings("ignore", message=".*verify_certs=False is insecure.*")
                from elasticsearch.exceptions import SecurityWarning
                warnings.filterwarnings("ignore", category=SecurityWarning)
            except Exception:
                pass

        try:
            client_args = {
                'hosts': [self.es_url],
                'verify_certs': self.verify_certs,
            }
            
            # Use API key if available
            if self.api_key:
                client_args['api_key'] = self.api_key
            # Otherwise use username/password if available
            elif self.username and self.password:
                client_args['basic_auth'] = (self.username, self.password)
            
            self.client = Elasticsearch(**client_args)
        except Exception as e:
            print(f"Warning: Failed to initialize Elasticsearch client: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if Elasticsearch is available."""
        if not self.client:
            return False
        
        try:
            # Try to get cluster info instead of just ping for better error messages
            info = self.client.info()
            if self.debug:
                print(
                    f"[Elastic] Connected successfully to {info.get('name', 'unknown')} "
                    f"(version {info.get('version', {}).get('number', 'unknown')})"
                )
            return True
        except Exception as e:
            print(f"[Elastic] Connection error: {type(e).__name__}: {e}")
            print(f"[Elastic] URL: {self.es_url}")
            auth_type = 'api_key'
            if self.api_key:
                if isinstance(self.api_key, tuple):
                    auth_type = f'api_key (tuple, ID: {self.api_key[0][:8]}...)'
                else:
                    auth_type = f'api_key (encoded, {self.api_key[:12]}...)'
            elif self.username:
                auth_type = 'basic_auth'
            else:
                auth_type = 'none'
            print(f"[Elastic] Auth: {auth_type}")
            return False
    
    def check_detection(
        self,
        process_name: Optional[str] = None,
        file_path: Optional[str] = None,
        time_window_seconds: int = 60,
        use_smart_filtering: bool = True,
        **kwargs
    ) -> List[DetectionResult]:
        """Check for Elastic Defend alerts."""
        
        if not self.is_available():
            print("Warning: Elasticsearch is not available")
            return []
        
        # Build time range
        now = datetime.utcnow()
        start_time = now - timedelta(seconds=time_window_seconds)
        
        if self.debug:
            print(f"\n[ELASTIC DEBUG]")
            print(f"  Time range: {start_time.isoformat()} to {now.isoformat()} ({time_window_seconds}s)")
            print(f"  Process filter: {process_name}")
            print(f"  File filter: {file_path}")
            print(f"  Smart filtering: {use_smart_filtering}")
            
            # Dump Session/Iteration info if available in kwargs
            # (Not usually passed, but good for future)
        
        # Build query
        must_clauses = [
            {
                "range": {
                    "@timestamp": {
                        "gte": start_time.isoformat() + "Z",
                        "lte": now.isoformat() + "Z"
                    }
                }
            }
        ]
        
        if use_smart_filtering and (process_name or file_path):
            should_clauses = []
            
            if process_name:
                base_name = os.path.splitext(process_name)[0]
                
                should_clauses.extend([
                    {"match": {"process.name": process_name}},
                    {"match": {"process.executable": process_name}},
                    {"wildcard": {"process.name": {"value": f"*{process_name}*", "case_insensitive": True}}},
                    {"wildcard": {"process.executable": {"value": f"*{process_name}*", "case_insensitive": True}}},
                    {"wildcard": {"process.name": {"value": f"*{base_name}*", "case_insensitive": True}}},
                    {"wildcard": {"process.parent.name": {"value": f"*{process_name}*", "case_insensitive": True}}},
                    {"wildcard": {"process.parent.executable": {"value": f"*{process_name}*", "case_insensitive": True}}},
                ])
            
            if file_path:
                file_name = os.path.basename(file_path)
                base_name = os.path.splitext(file_name)[0]
                
                should_clauses.extend([
                    {"match": {"file.path": file_path}},
                    {"match": {"file.name": file_name}},
                    {"wildcard": {"file.path": {"value": f"*{file_name}*", "case_insensitive": True}}},
                    {"wildcard": {"file.name": {"value": f"*{file_name}*", "case_insensitive": True}}},
                    {"wildcard": {"file.name": {"value": f"*{base_name}*", "case_insensitive": True}}},
                    {"wildcard": {"process.executable": {"value": f"*{file_name}*", "case_insensitive": True}}},
                    # Command lines (for scripts like python/csharp)
                    {"wildcard": {"process.command_line": {"value": f"*{file_name}*", "case_insensitive": True}}},
                    {"wildcard": {"process.parent.command_line": {"value": f"*{file_name}*", "case_insensitive": True}}},
                ])
            
            # kibana.alert.reason often contains process/file name in human-readable form
            if process_name:
                proc_base = os.path.splitext(process_name)[0]
                should_clauses.append({"wildcard": {"kibana.alert.reason": f"*{process_name}*"}})
                should_clauses.append({"wildcard": {"kibana.alert.reason": f"*{proc_base}*"}})
            if file_path:
                fn = os.path.basename(file_path)
                bn = os.path.splitext(fn)[0]
                should_clauses.append({"wildcard": {"kibana.alert.reason": f"*{fn}*"}})
                should_clauses.append({"wildcard": {"kibana.alert.reason": f"*{bn}*"}})
            
            must_clauses.append({
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            })
        
        elif process_name or file_path:
            if process_name:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"process.name": process_name}},
                            {"match": {"process.executable": process_name}},
                            {"wildcard": {"process.name": f"*{process_name}*"}}
                        ],
                        "minimum_should_match": 1
                    }
                })
            
            if file_path:
                file_name = os.path.basename(file_path)
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"file.path": file_path}},
                            {"match": {"file.name": file_name}},
                            {"match": {"process.executable": file_path}}
                        ],
                        "minimum_should_match": 1
                    }
                })
        
        query = {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "sort": [{"@timestamp": "desc"}],
            "size": 100
        }
        
        try:
            response = self.client.search(
                index=self.index_pattern,
                body=query
            )
            
            hits = response.get('hits', {}).get('hits', [])
            if hits:
                print(f"[Elastic] {len(hits)} alert(s) found")
            
            # Fallback: if filtered query returned 0 but we had filters, fetch all alerts in
            # time window and filter in Python (handles different field mappings / nesting)
            if len(hits) == 0 and (process_name or file_path) and use_smart_filtering:
                fallback_query = {
                    "query": {
                        "bool": {
                            "must": [{
                                "range": {
                                    "@timestamp": {
                                        "gte": start_time.isoformat() + "Z",
                                        "lte": now.isoformat() + "Z"
                                    }
                                }
                            }]
                        }
                    },
                    "sort": [{"@timestamp": "desc"}],
                    "size": 200
                }
                fallback_response = self.client.search(
                    index=self.index_pattern,
                    body=fallback_query
                )
                fallback_hits = fallback_response.get('hits', {}).get('hits', [])
                
                # --- NEW: Dump RAW alerts for debugging ---
                if self.debug and fallback_hits:
                    try:
                        import json
                        dump_file = "elastic_raw_hits.json"
                        with open(dump_file, "w", encoding="utf-8") as f:
                            json.dump([h.get('_source', {}) for h in fallback_hits], f, indent=2, default=str)
                        print(f"  [DEBUG] Dumped {len(fallback_hits)} raw alerts to {dump_file}")
                    except Exception as e:
                        print(f"  [DEBUG] Failed to dump raw alerts: {e}")
                # ------------------------------------------

                if self.debug:
                    print(
                        f"  Fallback: {len(fallback_hits)} total alert(s) in time window, "
                        "filtering by process/file..."
                    )
                
                search_terms = []
                if process_name:
                    search_terms.append(process_name.lower())
                    search_terms.append(os.path.splitext(process_name)[0].lower())
                if file_path:
                    fn = os.path.basename(file_path)
                    search_terms.append(fn.lower())
                    search_terms.append(os.path.splitext(fn)[0].lower())
                search_terms = list(dict.fromkeys(search_terms))  # unique, order preserved
                
                filtered_hits = []
                for hit in fallback_hits:
                    source = hit.get('_source', {})
                    text_parts = []
                    for obj, key in [(source.get('process', {}), 'name'), (source.get('process', {}), 'executable'),
                                     (source.get('process', {}), 'command_line'),
                                     (source.get('process', {}).get('parent', {}), 'command_line'),
                                     (source.get('process', {}).get('parent', {}), 'name'),
                                     (source.get('file', {}), 'path'), (source.get('file', {}), 'name')]:
                        if obj and isinstance(obj.get(key), str):
                            text_parts.append(obj[key].lower())
                    reason = source.get('kibana', {}).get('alert', {}).get('reason') or source.get('kibana.alert.reason') or ''
                    message = source.get('message') or ''
                    rule_name = source.get('kibana', {}).get('alert', {}).get('rule', {}).get('name') or source.get('kibana.alert.rule.name') or ''
                    
                    if isinstance(reason, str): text_parts.append(reason.lower())
                    if isinstance(message, str): text_parts.append(message.lower())
                    if isinstance(rule_name, str): text_parts.append(rule_name.lower())
                    haystack = ' '.join(text_parts)
                    if any(term in haystack for term in search_terms):
                        filtered_hits.append(hit)
                    elif self.debug:
                        pass # Verbose log suppressed to avoid noise unless needed
                        # p_name = source.get('process', {}).get('name')
                        # f_path = source.get('file', {}).get('path')
                        # r_name = source.get('kibana', {}).get('alert', {}).get('rule', {}).get('name')
                        # print(f"  [Filtered Out] Rule='{r_name}' | Proc='{p_name}' | File='{f_path}'")
                
                if filtered_hits:
                    if self.debug:
                        print(
                            f"  Fallback: {len(filtered_hits)} alert(s) match process/file "
                            "after client-side filter"
                        )
                    # Build a minimal response with only matching hits for _parse_alerts
                    response = {'hits': {'hits': filtered_hits}}
                    hits = filtered_hits
            
            if self.debug:
                # Debug: show a few alerts
                for i, hit in enumerate(hits[:2]):
                    source = hit.get('_source', {})
                    print(f"\n  Alert #{i+1}:")
                    print(f"    Rule: {source.get('kibana.alert.rule.name')}")
                    process = source.get('process', {})
                    print(f"    Process name: {process.get('name')}")
                    print(f"    Process exe: {process.get('executable')}")
                    print(f"    Parent: {process.get('parent', {}).get('name')}")
            
            return self._parse_alerts(response)
            
        except Exception as e:
            print(f"Error querying Elasticsearch: {e}")
            import traceback
            traceback.print_exc()
            return []

    def _parse_alerts(self, response: dict) -> List[DetectionResult]:
        """Parse Elasticsearch response into DetectionResult objects."""
        results = []
        
        hits = response.get('hits', {}).get('hits', [])
        
        for hit in hits:
            source = hit.get('_source', {})
            
            # Extract alert details
            rule_name = source.get('kibana.alert.rule.name') or source.get('signal.rule.name')
            description = source.get('kibana.alert.rule.description') or source.get('signal.rule.description')
            severity = source.get('kibana.alert.severity') or source.get('signal.rule.severity')
            
            # Extract process info
            process = source.get('process', {})
            process_name = process.get('name')
            process_id = process.get('pid')
            
            # Extract file info
            file_info = source.get('file', {})
            file_path = file_info.get('path') or process.get('executable')
            
            # Extract memory/behavior indicators
            details = {}
            
            # CRITICAL: Extract rule ID from multiple possible locations
            # This is the key to linking Elastic alerts to TOML behavior rules
            rule_id = (
                source.get('rule', {}).get('id') or  # Direct rule.id (most common)
                source.get('kibana.alert.rule.uuid') or  # Kibana format
                source.get('kibana', {}).get('alert', {}).get('rule', {}).get('uuid') or  # Nested format
                source.get('signal.rule.id')  # Legacy signal format
            )
            if rule_id:
                details['rule_id'] = rule_id
                if self.debug:
                    print(f"  [Alert] Rule ID: {rule_id}")
            
            # Check for memory-related indicators
            if 'memory_protection' in str(source):
                details['memory_protection'] = source.get('process', {}).get('memory_protection', {})
            
            # Extract threat information
            threat = source.get('threat', {})
            if threat:
                details['threat'] = threat
            
            # Look for specific detection reasons
            reason = source.get('kibana.alert.reason') or source.get('signal.reason')
            if reason:
                details['reason'] = reason
            
            # Memory indicators from Elastic Defend
            memory_region = source.get('Memory.allocation_type')
            if memory_region:
                details['memory_allocation_type'] = memory_region
            
            pe_signer = source.get('process', {}).get('code_signature', {})
            if pe_signer:
                details['code_signature'] = pe_signer
            
            # Raw alert data for AI analysis
            import json
            raw_alert = json.dumps(source, indent=2, default=str)
            
            result = DetectionResult(
                detected=True,
                detector_name="elastic",
                rule_name=rule_name,
                description=description,
                severity=severity,
                process_name=process_name,
                process_id=process_id,
                file_path=file_path,
                details=details,
                raw_alert=raw_alert[:2000]  # Limit size
            )
            
            results.append(result)
        
        return results
    
    def get_recent_memory_alerts(self, time_window_seconds: int = 300) -> List[DetectionResult]:
        """Get recent memory-related alerts.
        
        Useful for finding shellcode injection, memory allocation alerts.
        """
        if not self.is_available():
            return []
        
        now = datetime.utcnow()
        start_time = now - timedelta(seconds=time_window_seconds)
        
        # Query for memory-related alerts
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat() + "Z",
                                    "lte": now.isoformat() + "Z"
                                }
                            }
                        }
                    ],
                    "should": [
                        {"match": {"kibana.alert.rule.name": "memory"}},
                        {"match": {"kibana.alert.rule.name": "shellcode"}},
                        {"match": {"kibana.alert.rule.name": "injection"}},
                        {"match": {"kibana.alert.rule.name": "unbacked"}},
                        {"match": {"process.Ext.memory_region.protection": "RWX"}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [{"@timestamp": "desc"}],
            "size": 50
        }
        
        try:
            response = self.client.search(
                index=self.index_pattern,
                body=query
            )
            return self._parse_alerts(response)
        except Exception as e:
            print(f"Error querying memory alerts: {e}")
            return []
