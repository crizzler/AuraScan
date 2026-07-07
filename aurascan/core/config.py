import os
import sys
from pathlib import Path

MAX_SCRIPT_SIZE = 5 * 1024 * 1024 # 5 MB

def load_env():
    env_paths = [
        Path("/etc/aurascan/.env"),
        Path.home() / ".config" / "aurascan" / ".env",
    ]
    for env_file in env_paths:
        if env_file.exists():
            try:
                with open(env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, val = line.split('=', 1)
                            os.environ[key.strip()] = val.strip().strip('"\'')
            except Exception as e:
                print(f"[AuraScan] Warning: Failed to read {env_file}: {e}", file=sys.stderr)
