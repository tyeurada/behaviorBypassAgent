
import os
import sys
import json
import datetime
from lib.detectors.elastic import ElasticDetector
from core.utils import load_config

def main():
    print("--- Debug Elastic Filter ---")
    
    # Load config
    try:
        config = load_config()
    except Exception as e:
        print(f"Error loading config: {e}")
        return

    elastic_config = config.get('detectors', {}).get('elastic', {})
    if not elastic_config:
        print("Error: No elastic config found.")
        return

    # Force debug to True for the detector instance
    elastic_config['debug'] = True
    
    detector = ElasticDetector(elastic_config)
    
    if not detector.is_available():
        print("Error: Elastic is not available.")
        return

    print("Elastic connected.")
    
    # 1. Fetch RAW alerts (last 1 hour)
    print("\n[Step 1] Fetching ALL alerts (last 60 mins)...")
    raw_alerts = detector.check_detection(
        process_name=None, 
        file_path=None, 
        time_window_seconds=3600,
        use_smart_filtering=False
    )
    
    print(f"Found {len(raw_alerts)} raw alerts.")
    
    # Dump raw alerts to file
    raw_dump = [a.to_dict() for a in raw_alerts]
    with open("debug_elastic_raw.json", "w", encoding="utf-8") as f:
        json.dump(raw_dump, f, indent=2, default=str)
    print("Saved raw alerts to 'debug_elastic_raw.json'.")
    
    # 2. Fetch FILTERED alerts (simulating the agent's check)
    # We suspect 'loader_1.exe' or similar might be the process name
    # Let's try to guess from raw alerts if any exist
    target_process = "loader_1.exe"
    if raw_alerts:
        # Try to find a process name from raw alerts that looks like our loader
        for a in raw_alerts:
            p_name = a.process_name
            if p_name and "loader" in p_name.lower():
                target_process = p_name
                print(f"Detected potential target process from logs: {target_process}")
                break
    
    print(f"\n[Step 2] Fetching FILTERED alerts for '{target_process}'...")
    filtered_alerts = detector.check_detection(
        process_name=target_process,
        file_path=None, # We don't know the exact path the agent used, but usually process_name is enough for smart filter
        time_window_seconds=3600,
        use_smart_filtering=True
    )
    
    print(f"Found {len(filtered_alerts)} filtered alerts.")
    
    # 3. Analyze differences
    raw_ids = set(a.details.get('rule_id') or a.rule_name for a in raw_alerts)
    filtered_ids = set(a.details.get('rule_id') or a.rule_name for a in filtered_alerts)
    
    missing = raw_ids - filtered_ids
    print(f"\nMissing Rule IDs/Names in filtered set: {missing}")
    
    for a in raw_alerts:
        if (a.details.get('rule_id') or a.rule_name) in missing:
            print(f"\n[MISSING] {a.rule_name}")
            print(f"  Process: {a.process_name}")
            print(f"  File: {a.file_path}")
            print(f"  Reason: {a.details.get('reason')}")

if __name__ == "__main__":
    main()
