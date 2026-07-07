import sqlite3
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any

class ScanCache:
    def __init__(self, cache_dir: Path = Path.home() / ".cache" / "aurascan"):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "scancache.db"
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    hash_key TEXT PRIMARY KEY,
                    finding_json TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def _generate_hash(
        self,
        file_path: str,
        scanner_version: str,
        rule_version: str,
        *,
        clamav_db_version: str = "",
        ai_prompt_version: str = "",
        config_flags: Optional[Dict[str, Any]] = None,
        scan_phase: str = "",
        history_snapshot_hash: str = "",
    ) -> str:
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
        except Exception:
            return "" # Cannot hash, skip cache

        key_material = {
            "scanner_version": scanner_version,
            "rule_version": rule_version,
            "clamav_db_version": clamav_db_version,
            "ai_prompt_version": ai_prompt_version,
            "config_flags": config_flags or {},
            "scan_phase": scan_phase,
            "history_snapshot_hash": history_snapshot_hash,
        }
        sha256_hash.update(json.dumps(key_material, sort_keys=True).encode("utf-8"))
        return sha256_hash.hexdigest()

    def get_cached_result(self, file_path: str, scanner_version: str, rule_version: str, **key_parts) -> Optional[Dict]:
        hash_key = self._generate_hash(file_path, scanner_version, rule_version, **key_parts)
        if not hash_key:
            return None

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT finding_json FROM cache WHERE hash_key = ?", (hash_key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
        return None

    def set_cached_result(self, file_path: str, scanner_version: str, rule_version: str, result_dict: Dict, **key_parts):
        hash_key = self._generate_hash(file_path, scanner_version, rule_version, **key_parts)
        if not hash_key:
            return

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (hash_key, finding_json) VALUES (?, ?)",
                (hash_key, json.dumps(result_dict))
            )
