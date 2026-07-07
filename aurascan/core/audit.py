import sys
import datetime
from pathlib import Path

def log_audit(pkg_path: str, reasons: list):
    log_dir = Path.home() / '.local' / 'share' / 'aurascan'
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / 'audit.log'
    timestamp = datetime.datetime.now().isoformat()
    try:
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] BLOCKED: {pkg_path}\n")
            for r in reasons:
                f.write(f"  -> {r}\n")
    except Exception as e:
        print(f"[AuraScan] WARNING: Could not write to audit log: {e}", file=sys.stderr)
