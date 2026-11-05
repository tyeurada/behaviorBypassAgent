
from pathlib import Path

import yaml
from dotenv import load_dotenv


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into ``base`` (override wins)."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load configuration from YAML file.

    If a sibling ``config.local.yaml`` (or ``.yml``) exists next to the base
    file, it is deep-merged over the base config. The local file is
    gitignored and intended for machine-specific settings (endpoints,
    model names, credentials-hosts) that must not be committed.
    """
    # Load .env variables
    load_dotenv()

    path = Path(config_path)
    if not path.exists():
        # Try relative to project root
        root = Path(__file__).parent.parent
        path = root / config_path

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, encoding='utf-8') as f:
        config = yaml.safe_load(f)

    # Machine-local overrides (gitignored): config/config.local.yaml
    for local_name in ("config.local.yaml", "config.local.yml"):
        local_path = path.parent / local_name
        if local_path.exists():
            with open(local_path, encoding='utf-8') as f:
                local_config = yaml.safe_load(f) or {}
            config = _deep_merge(config, local_config)
            break

    # Helper to resolve paths in config
    root_dir = Path(__file__).parent.parent.absolute()

    # Resolve relative paths in config/behavior_rules/directory
    if 'behavior_rules' in config and 'directory' in config['behavior_rules']:
        rules_dir = Path(config['behavior_rules']['directory'])
        if not rules_dir.is_absolute():
            config['behavior_rules']['directory'] = str(root_dir / rules_dir)

    return config
