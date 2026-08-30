"""
Optional configuration file support.

Looks for ~/.config/subhunter/config.yaml by default. Entirely optional —
if the file doesn't exist, or PyYAML isn't installed, SubHunter runs fine
with just CLI defaults. CLI arguments always take precedence over config values.
"""

import os

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/subhunter/config.yaml")

DEFAULTS = {
    "concurrency": 300,
    "dns_timeout": 3.0,
    "dns_retries": 1,
    "http_timeout": 5,
    "resolvers": None,
}


def load_config(path=None):
    """
    Returns a dict of settings. Falls back to DEFAULTS if the file is
    missing or PyYAML isn't installed — never raises.
    """
    config = dict(DEFAULTS)
    path = path or DEFAULT_CONFIG_PATH

    if not os.path.isfile(path):
        return config

    try:
        import yaml
    except ImportError:
        return config  # optional dependency not installed — silently skip

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
        for key in DEFAULTS:
            if key in data:
                config[key] = data[key]
    except Exception:
        pass  # malformed config should never crash the tool

    return config
