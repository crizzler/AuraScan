import os
import pwd
import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional

MAX_SCRIPT_SIZE = 5 * 1024 * 1024  # 5 MB
SYSTEM_ENV_PATH = Path("/etc/aurascan/.env")

ENV_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
SECRET_KEY_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD")


def user_config_dir(home: Optional[Path] = None) -> Path:
    return (home or Path.home()) / ".config" / "aurascan"


def user_env_path() -> Path:
    return user_config_dir() / ".env"


def env_paths(env: Optional[Mapping[str, str]] = None) -> Iterable[Path]:
    paths: List[Path] = [
        SYSTEM_ENV_PATH,
        user_env_path(),
    ]
    invoking_user_path = invoking_user_env_path(env)
    if invoking_user_path is not None and invoking_user_path not in paths:
        paths.append(invoking_user_path)
    return paths


def invoking_user_env_path(env: Optional[Mapping[str, str]] = None) -> Optional[Path]:
    if os.geteuid() != 0:
        return None
    source = env if env is not None else os.environ
    username = source.get("SUDO_USER", "").strip() or source.get("DOAS_USER", "").strip()
    if not username or username == "root":
        return None
    try:
        user_home = Path(pwd.getpwnam(username).pw_dir)
    except KeyError:
        return None
    if not user_home.is_absolute():
        return None
    return user_config_dir(user_home) / ".env"


def parse_env_lines(lines: Iterable[str]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, val = stripped.split("=", 1)
        values[key.strip()] = val.strip().strip('"\'')
    return values


def read_env_file(path: Path) -> Dict[str, str]:
    with open(path, "r", encoding="utf-8") as handle:
        return parse_env_lines(handle)


def load_env(paths: Optional[Iterable[Path]] = None):
    for env_file in paths if paths is not None else env_paths():
        if env_file.exists():
            try:
                os.environ.update(read_env_file(env_file))
            except Exception as e:
                print(f"[AuraScan] Warning: Failed to read {env_file}: {e}", file=sys.stderr)


def ensure_user_config_dir(path: Optional[Path] = None) -> Path:
    config_dir = path or user_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(config_dir, 0o700)
    except OSError:
        pass
    return config_dir


def _line_key(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return ""
    key, _value = stripped.split("=", 1)
    key = key.strip()
    return key if ENV_KEY_PATTERN.match(key) else ""


def _format_env_line(key: str, value: str) -> str:
    if not ENV_KEY_PATTERN.match(key):
        raise ValueError(f"invalid AuraScan environment key: {key}")
    if "\n" in value or "\r" in value:
        raise ValueError(f"invalid newline in value for {key}")
    return f"{key}={value}"


def write_user_env(updates: Mapping[str, str], path: Optional[Path] = None) -> Path:
    env_file = path or user_env_path()
    ensure_user_config_dir(env_file.parent)

    existing_lines = []
    if env_file.exists():
        existing_lines = env_file.read_text(encoding="utf-8").splitlines()

    updated_lines = []
    seen = set()
    for line in existing_lines:
        key = _line_key(line)
        if key and key in updates:
            updated_lines.append(_format_env_line(key, str(updates[key])))
            seen.add(key)
        else:
            updated_lines.append(line)

    for key, value in updates.items():
        if key not in seen:
            updated_lines.append(_format_env_line(key, str(value)))

    content = "\n".join(updated_lines).rstrip() + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".env.", dir=str(env_file.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, env_file)
        os.chmod(env_file, 0o600)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return env_file


def file_mode(path: Path) -> Optional[int]:
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return None


def is_secret_key(key: str) -> bool:
    upper = key.upper()
    return any(marker in upper for marker in SECRET_KEY_MARKERS)


def redact_config_value(key: str, value: str) -> str:
    if not value:
        return ""
    if is_secret_key(key):
        return "<redacted>"
    return value


def redact_env(values: Mapping[str, str]) -> Dict[str, str]:
    return {key: redact_config_value(key, value) for key, value in values.items()}
