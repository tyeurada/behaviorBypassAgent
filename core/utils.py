
import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load configuration from YAML file."""
    # Load .env variables
    load_dotenv()
    
    path = Path(config_path)
    if not path.exists():
        # Try relative to project root
        root = Path(__file__).parent.parent
        path = root / config_path
        
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
        
    with open(path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
        
    # Helper to resolve paths in config
    root_dir = Path(__file__).parent.parent.absolute()
    
    # Resolve relative paths in config/behavior_rules/directory
    if 'behavior_rules' in config and 'directory' in config['behavior_rules']:
        rules_dir = Path(config['behavior_rules']['directory'])
        if not rules_dir.is_absolute():
            config['behavior_rules']['directory'] = str(root_dir / rules_dir)

    return config
