import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen as urllib_urlopen

from aurascan.core.models import SCANNER_VERSION, Severity


SECURITY_AUDIT_SCHEMA_VERSION = "1.0"
CAMPAIGN_MANIFEST_ASSET = "aur-campaign-2026-06-11.json"
CAMPAIGN_PACKAGES_ASSET = "aur-campaign-2026-06-11-packages.txt"
MAX_CAMPAIGN_BYTES = 2 * 1024 * 1024
MAX_CAMPAIGN_PACKAGES = 20_000
MAX_PACMAN_LOG_BYTES = 4 * 1024 * 1024
MAX_CACHE_ENTRIES = 10_000
DEFAULT_FEED_TIMEOUT = 20
MAX_HOST_INDICATOR_BYTES = 128 * 1024
MAX_HOST_INDICATOR_ENTRIES = 4096
EXIT_SECURITY_ALERT = 1
EXIT_SECURITY_AUDIT_UNAVAILABLE = 2
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9@._+][A-Za-z0-9@._+:-]{0,254}$")
PACMAN_HISTORY_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+\[ALPM\]\s+"
    r"(?P<action>installed|upgraded|downgraded|reinstalled|removed)\s+"
    r"(?P<package>\S+)\s+\((?P<version>[^)]*)\)"
)
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
HYPRLAND_FIXES_INCIDENT_PACKAGE = "hyprland-fixes"
HYPRLAND_FIXES_INCIDENT_REFERENCE = (
    "https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/"
    "message/TAASU6LTO76UCKYLMG25OJPUY7ZONASN/"
)
HYPRLAND_FIXES_SOURCE_COMMIT_REFERENCE = (
    "https://github.com/iusearch-hyprlandbtw/hyprland-fixes/"
    "commit/d9812f5e31adbadd1027d9f578bbe28016fb139a"
)
HYPRLAND_FIXES_TAILSCALE_PEER = "100.70.123.108"
HYPRLAND_FIXES_ARTIFACT_PATHS = (
    "/etc/hyprland-fixes",
    "/usr/lib/hyprland-fixes",
    "/usr/bin/hyprland-fixes",
    "/etc/systemd/system/hyprland-fixes.service",
    "/etc/systemd/system/hyprland-fixes.timer",
    "/usr/lib/systemd/system/arch-mirrorlist-criteria.service",
    "/etc/systemd/system/arch-keyring-syncer.service",
    "/etc/pacman.d/mirrorlist-criteria",
    "/etc/pacman.d/keyring-syncer",
    "/etc/userkeys",
    "/etc/system-functions",
    "/root/pamkeys",
    "/etc/sudoers.d/hyprland-fixes-permissions",
    "/etc/arch-mirror-sync",
    "/usr/lib/arch-mirror-sync",
    "/usr/local/bin/arch-mirror-sync",
    "/etc/systemd/system/arch-mirror-sync.service",
    "/etc/systemd/system/arch-mirror-sync.timer",
)


@dataclass
class CampaignIntel:
    campaign_id: str
    title: str
    source_url: str
    official_reference: str
    source_kind: str
    window_start: date
    window_end: date
    package_names: Set[str]
    payload_indicators: List[str]
    sha256: str
    retrieved_at: str
    data_origin: str = "bundled"

    def to_dict(self) -> Dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "title": self.title,
            "source_url": self.source_url,
            "official_reference": self.official_reference,
            "source_kind": self.source_kind,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "package_count": len(self.package_names),
            "payload_indicators": list(self.payload_indicators),
            "sha256": self.sha256,
            "retrieved_at": self.retrieved_at,
            "data_origin": self.data_origin,
        }


@dataclass
class PacmanHistoryRecord:
    timestamp: str
    action: str
    package: str
    version: str

    @property
    def event_date(self) -> Optional[date]:
        try:
            return date.fromisoformat(self.timestamp[:10])
        except (TypeError, ValueError):
            return None

    def to_dict(self) -> Dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "package": self.package,
            "version": self.version,
        }


@dataclass
class SecurityFinding:
    rule_id: str
    severity: Severity
    category: str
    title: str
    summary: str
    why_it_matters: str
    recommended_action: str
    package_name: str = ""
    evidence: List[str] = field(default_factory=list)
    confidence: str = "medium"
    source: str = "deterministic"

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity(str(self.severity))

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "recommended_action": self.recommended_action,
            "package_name": self.package_name,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class ArchAuditResult:
    status: str = "not_run"
    findings: List[SecurityFinding] = field(default_factory=list)
    error: str = ""
    command: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "status": self.status,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "error": self.error,
            "command": list(self.command),
        }


@dataclass
class SecurityAuditReport:
    campaign: Optional[CampaignIntel]
    findings: List[SecurityFinding] = field(default_factory=list)
    arch_audit: ArchAuditResult = field(default_factory=ArchAuditResult)
    installed_package_count: int = 0
    history_record_count: int = 0
    helper_cache_entry_count: int = 0
    history_truncated: bool = False
    notes: List[str] = field(default_factory=list)
    status: str = "ok"
    schema_version: str = SECURITY_AUDIT_SCHEMA_VERSION
    scanner_version: str = SCANNER_VERSION

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.LOW
        return max((item.severity for item in self.findings), key=SEVERITY_ORDER.index)

    @property
    def has_alert(self) -> bool:
        return self.highest_severity in {Severity.HIGH, Severity.CRITICAL}

    @property
    def campaign_findings(self) -> List[SecurityFinding]:
        return [item for item in self.findings if item.category == "aur_campaign"]

    @property
    def official_vulnerability_findings(self) -> List[SecurityFinding]:
        return [item for item in self.findings if item.category == "official_vulnerability"]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "scanner_version": self.scanner_version,
            "report_type": "security_audit",
            "status": self.status,
            "risk_summary": {
                "severity": self.highest_severity.value,
                "requires_attention": self.has_alert,
                "known_campaign_matches": len(self.campaign_findings),
                "official_vulnerability_findings": len(self.official_vulnerability_findings),
                "clean_proof": False,
            },
            "campaign": self.campaign.to_dict() if self.campaign else None,
            "collection": {
                "installed_package_count": self.installed_package_count,
                "history_record_count": self.history_record_count,
                "history_truncated": self.history_truncated,
                "helper_cache_entry_count": self.helper_cache_entry_count,
            },
            "arch_audit": self.arch_audit.to_dict(),
            "findings": [item.to_dict() for item in self.sorted_findings()],
            "notes": list(self.notes),
            "limitations": [
                "A package-name match is exposure evidence, not proof that a particular malicious commit executed.",
                "No match means no known match in the loaded intelligence; it does not prove system integrity.",
                "AuraScan does not automatically remove packages or clean a potentially compromised host.",
            ],
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def sorted_findings(self) -> List[SecurityFinding]:
        indexed = list(enumerate(self.findings))
        indexed.sort(key=lambda item: (-SEVERITY_ORDER.index(item[1].severity), item[0]))
        return [finding for _, finding in indexed]

    def render_terminal(self, *, verbose: bool = False, use_color: bool = True) -> str:
        reset = "\033[0m" if use_color else ""
        red = "\033[91m" if use_color else ""
        yellow = "\033[93m" if use_color else ""
        green = "\033[92m" if use_color else ""
        color = red if self.has_alert else yellow if self.findings or self.status != "ok" else green
        campaign_label = "unavailable"
        if self.campaign:
            campaign_label = (
                f"{self.campaign.title} ({len(self.campaign.package_names)} names, "
                f"{self.campaign.data_origin}; {self.campaign.source_kind})"
            )
        lines = [
            "\n[AuraScan] Security Audit",
            "=" * 54,
            f"Risk: {color}{self.highest_severity.value}{reset} | Status: {self.status.upper()}",
            f"AUR campaign intelligence: {campaign_label}",
            (
                f"Packages checked: {self.installed_package_count} | "
                f"Pacman history records: {self.history_record_count}"
            ),
            f"Official package advisories: {self._arch_audit_summary()}",
            "-" * 54,
        ]
        if self.campaign is None:
            lines.append("[WARN] Known AUR campaign intelligence was unavailable, so that check is incomplete.")
        elif not self.campaign_findings:
            lines.append("[OK] No known AUR campaign package or campaign-window history matches were found.")
        if not self.official_vulnerability_findings and self.arch_audit.status == "ok":
            lines.append("[OK] arch-audit reported no applicable official-package advisories.")

        findings = self.sorted_findings()
        visible = findings if verbose else findings[:5]
        if visible:
            lines.append("Security findings:")
            for index, finding in enumerate(visible, start=1):
                lines.append(f"{index}. {finding.title} [{finding.severity.value}]")
                lines.append(finding.summary)
                lines.append(f"Why it matters: {finding.why_it_matters}")
                lines.append(f"Recommended action: {finding.recommended_action}")
                if verbose and finding.evidence:
                    lines.append("Evidence: " + "; ".join(finding.evidence[:8]))
                lines.append("")
            if lines[-1] == "":
                lines.pop()
        hidden = len(findings) - len(visible)
        if hidden:
            lines.append(f"{hidden} additional finding(s) hidden. Use --verbose to show all.")
        if self.notes:
            lines.append("Collection notes:")
            for note in self.notes if verbose else self.notes[:4]:
                lines.append(f"- {note}")
        lines.append(
            "\nA clean-looking result means no known match was found; it is not proof that package code or the system is safe."
        )
        if self.has_alert:
            lines.append("Recommended Action: Treat the matched evidence as an incident and investigate from trusted media.")
        elif self.findings:
            lines.append("Recommended Action: Review the advisory context and apply normal signed repository updates.")
        else:
            lines.append("Recommended Action: No campaign-specific response is indicated by the available evidence.")
        return "\n".join(lines)

    def _arch_audit_summary(self) -> str:
        if self.arch_audit.status == "ok":
            count = len(self.arch_audit.findings)
            return "no findings" if count == 0 else f"{count} finding(s)"
        if self.arch_audit.status == "not_installed":
            return "not checked (arch-audit is not installed)"
        if self.arch_audit.status == "skipped_offline":
            return "skipped in offline mode"
        if self.arch_audit.error:
            return f"{self.arch_audit.status} ({self.arch_audit.error})"
        return self.arch_audit.status


def _asset_path(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "assets" / name


def default_security_state_root(env: Optional[Mapping[str, str]] = None) -> Path:
    source = env if env is not None else os.environ
    state_home = source.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "aurascan" / "security-intel"


def parse_campaign_package_names(text: str) -> Set[str]:
    if len(text.encode("utf-8")) > MAX_CAMPAIGN_BYTES:
        raise ValueError("campaign feed exceeds the bounded size limit")
    names: Set[str] = set()
    invalid_count = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        name = raw_line.strip()
        if not name or name.startswith("#"):
            continue
        if len(name) >= 2 and name[0] == name[-1] and name[0] in {"'", '"'}:
            name = name[1:-1]
        if not PACKAGE_NAME_RE.fullmatch(name):
            invalid_count += 1
            if invalid_count > 16:
                raise ValueError("campaign feed contains too many invalid package names")
            continue
        names.add(name)
        if len(names) > MAX_CAMPAIGN_PACKAGES:
            raise ValueError("campaign feed exceeds the package-count limit")
    if not names:
        raise ValueError("campaign feed contains no package names")
    return names


def _read_bounded_text(path: Path, limit: int = MAX_CAMPAIGN_BYTES) -> str:
    with path.open("rb") as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"{path.name} exceeds the bounded size limit")
    return payload.decode("utf-8", errors="strict")


def _load_manifest(path: Path) -> Dict[str, object]:
    data = json.loads(_read_bounded_text(path, 256 * 1024))
    if not isinstance(data, dict):
        raise ValueError("campaign manifest must be a JSON object")
    required = {
        "campaign_id",
        "title",
        "source_url",
        "official_reference",
        "source_kind",
        "window_start",
        "window_end",
        "payload_indicators",
        "package_count",
        "package_list_sha256",
        "retrieved_at",
    }
    missing = sorted(required - set(data))
    if missing:
        raise ValueError("campaign manifest is missing: " + ", ".join(missing))
    if not str(data["source_url"]).startswith("https://"):
        raise ValueError("campaign source URL must use HTTPS")
    if not str(data["official_reference"]).startswith("https://archlinux.org/"):
        raise ValueError("official campaign reference must use archlinux.org")
    return data


def _campaign_from_data(
    manifest: Mapping[str, object],
    package_text: str,
    *,
    data_origin: str,
    expected_sha256: Optional[str] = None,
    retrieved_at: Optional[str] = None,
) -> CampaignIntel:
    payload = package_text.encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    expected = str(expected_sha256 or manifest.get("package_list_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or digest != expected:
        raise ValueError("campaign package-list SHA-256 does not match its manifest")
    names = parse_campaign_package_names(package_text)
    expected_count = int(manifest.get("package_count") or 0)
    if data_origin == "bundled" and expected_count != len(names):
        raise ValueError("campaign package count does not match its manifest")
    indicators = manifest.get("payload_indicators")
    if not isinstance(indicators, list) or not all(isinstance(item, str) and item for item in indicators):
        raise ValueError("campaign payload indicators are invalid")
    return CampaignIntel(
        campaign_id=str(manifest["campaign_id"]),
        title=str(manifest["title"]),
        source_url=str(manifest["source_url"]),
        official_reference=str(manifest["official_reference"]),
        source_kind=str(manifest["source_kind"]),
        window_start=date.fromisoformat(str(manifest["window_start"])),
        window_end=date.fromisoformat(str(manifest["window_end"])),
        package_names=names,
        payload_indicators=list(indicators),
        sha256=digest,
        retrieved_at=str(retrieved_at or manifest["retrieved_at"]),
        data_origin=data_origin,
    )


def load_campaign_intel(
    *,
    manifest_path: Optional[Path] = None,
    package_list_path: Optional[Path] = None,
    state_root: Optional[Path] = None,
) -> Tuple[CampaignIntel, List[str]]:
    manifest_file = Path(manifest_path or _asset_path(CAMPAIGN_MANIFEST_ASSET))
    package_file = Path(package_list_path or _asset_path(CAMPAIGN_PACKAGES_ASSET))
    manifest = _load_manifest(manifest_file)
    notes: List[str] = []
    cache_root = Path(state_root or default_security_state_root())
    cache_list = cache_root / CAMPAIGN_PACKAGES_ASSET
    cache_meta = cache_root / (CAMPAIGN_PACKAGES_ASSET + ".meta.json")
    if cache_list.is_file() and cache_meta.is_file():
        try:
            metadata = json.loads(_read_bounded_text(cache_meta, 64 * 1024))
            if not isinstance(metadata, dict):
                raise ValueError("cache metadata is not an object")
            if str(metadata.get("source_url") or "") != str(manifest["source_url"]):
                raise ValueError("cache source URL does not match the packaged manifest")
            cached = _campaign_from_data(
                manifest,
                _read_bounded_text(cache_list),
                data_origin="refreshed-cache",
                expected_sha256=str(metadata.get("sha256") or ""),
                retrieved_at=str(metadata.get("retrieved_at") or ""),
            )
            return cached, notes
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            notes.append(f"Ignored invalid cached campaign intelligence: {exc}")
    bundled = _campaign_from_data(
        manifest,
        _read_bounded_text(package_file),
        data_origin="bundled",
    )
    return bundled, notes


def refresh_campaign_intel(
    campaign: CampaignIntel,
    *,
    state_root: Optional[Path] = None,
    urlopen: Callable = urllib_urlopen,
    timeout: int = DEFAULT_FEED_TIMEOUT,
) -> CampaignIntel:
    request = Request(
        campaign.source_url,
        headers={
            "Accept": "text/plain",
            "User-Agent": f"AuraScan/{SCANNER_VERSION} security-intel",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        final_url = response.geturl() if hasattr(response, "geturl") else campaign.source_url
        expected_url = urlparse(campaign.source_url)
        resolved_url = urlparse(str(final_url))
        if resolved_url.scheme != "https" or resolved_url.hostname != expected_url.hostname:
            raise ValueError("campaign feed redirected outside its approved HTTPS host")
        content_length = response.headers.get("Content-Length") if hasattr(response, "headers") else None
        if content_length and int(content_length) > MAX_CAMPAIGN_BYTES:
            raise ValueError("remote campaign feed exceeds the bounded size limit")
        payload = response.read(MAX_CAMPAIGN_BYTES + 1)
    if len(payload) > MAX_CAMPAIGN_BYTES:
        raise ValueError("remote campaign feed exceeds the bounded size limit")
    text = payload.decode("utf-8", errors="strict")
    names = parse_campaign_package_names(text)
    digest = hashlib.sha256(payload).hexdigest()
    retrieved_at = datetime.now(timezone.utc).isoformat()
    root = Path(state_root or default_security_state_root())
    _ensure_private_dir(root)
    list_path = root / CAMPAIGN_PACKAGES_ASSET
    meta_path = root / (CAMPAIGN_PACKAGES_ASSET + ".meta.json")
    _atomic_private_write(list_path, payload)
    metadata = {
        "schema_version": "1.0",
        "source_url": campaign.source_url,
        "sha256": digest,
        "retrieved_at": retrieved_at,
        "package_count": len(names),
    }
    _atomic_private_write(meta_path, (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return CampaignIntel(
        campaign_id=campaign.campaign_id,
        title=campaign.title,
        source_url=campaign.source_url,
        official_reference=campaign.official_reference,
        source_kind=campaign.source_kind,
        window_start=campaign.window_start,
        window_end=campaign.window_end,
        package_names=names,
        payload_indicators=list(campaign.payload_indicators),
        sha256=digest,
        retrieved_at=retrieved_at,
        data_origin="refreshed-cache",
    )


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _atomic_private_write(path: Path, payload: bytes) -> None:
    _ensure_private_dir(path.parent)
    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(dir=str(path.parent), delete=False) as handle:
            temp_name = handle.name
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        path.chmod(0o600)
    finally:
        if temp_name:
            try:
                Path(temp_name).unlink()
            except FileNotFoundError:
                pass


def _run_capture(runner: Callable, command: Sequence[str], *, timeout: int = 30):
    return runner(
        list(command),
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def collect_installed_packages(
    *,
    runner: Callable = subprocess.run,
    root: Path = Path("/"),
) -> Tuple[Dict[str, str], str]:
    command = ["pacman"]
    if root != Path("/"):
        command.extend(["--root", str(root), "--dbpath", str(root / "var/lib/pacman")])
    command.append("-Q")
    try:
        result = _run_capture(runner, command)
    except (OSError, subprocess.SubprocessError) as exc:
        return {}, str(exc)
    if int(getattr(result, "returncode", 0)) != 0:
        return {}, str(getattr(result, "stderr", "") or "pacman package query failed").strip()
    packages: Dict[str, str] = {}
    for line in str(getattr(result, "stdout", "") or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and PACKAGE_NAME_RE.fullmatch(parts[0]):
            packages[parts[0]] = parts[1].strip()
    return packages, ""


def parse_pacman_history(text: str) -> List[PacmanHistoryRecord]:
    records: List[PacmanHistoryRecord] = []
    for line in text.splitlines():
        match = PACMAN_HISTORY_RE.match(line)
        if not match:
            continue
        records.append(PacmanHistoryRecord(**match.groupdict()))
    return records


def collect_pacman_history(
    *,
    root: Path = Path("/"),
    log_paths: Optional[Iterable[Path]] = None,
) -> Tuple[List[PacmanHistoryRecord], bool, List[str]]:
    paths = (
        list(log_paths)
        if log_paths is not None
        else [root / "var/log/pacman.log", root / "var/log/pacman.log.1"]
    )
    records: List[PacmanHistoryRecord] = []
    truncated = False
    notes: List[str] = []
    for path in paths:
        path = Path(path)
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                if size > MAX_PACMAN_LOG_BYTES:
                    truncated = True
                    handle.seek(size - MAX_PACMAN_LOG_BYTES)
                    handle.readline()
                payload = handle.read(MAX_PACMAN_LOG_BYTES + 1)
            if len(payload) > MAX_PACMAN_LOG_BYTES:
                payload = payload[-MAX_PACMAN_LOG_BYTES:]
                truncated = True
            records.extend(parse_pacman_history(payload.decode("utf-8", errors="replace")))
        except OSError as exc:
            notes.append(f"Could not read {path}: {exc}")
    if not paths or not any(path.is_file() for path in paths):
        notes.append("No pacman history log was available for campaign-window correlation.")
    if truncated:
        notes.append("Pacman history was bounded to the newest 4 MiB per log file.")
    return records, truncated, notes


def scan_helper_cache_names(
    home: Optional[Path],
    campaign_names: Set[str],
) -> Tuple[Set[str], int, bool]:
    if home is None:
        return set(), 0, False
    roots = (
        home / ".cache/paru/clone",
        home / ".cache/yay",
        home / ".cache/shelly",
    )
    matched: Set[str] = set()
    count = 0
    truncated = False
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        try:
            for entry in os.scandir(root):
                count += 1
                if count > MAX_CACHE_ENTRIES:
                    truncated = True
                    return matched, count - 1, truncated
                if entry.name in campaign_names:
                    matched.add(entry.name)
        except OSError:
            continue
    return matched, count, truncated


def audit_hyprland_fixes_exposure(
    installed_packages: Mapping[str, str],
    history: Sequence[PacmanHistoryRecord],
    *,
    pending_package_names: Optional[Iterable[str]] = None,
    helper_cache_names: Optional[Iterable[str]] = None,
) -> List[SecurityFinding]:
    """Correlate bounded package state with the reported malicious package."""

    incident_records = [
        record for record in history
        if record.package == HYPRLAND_FIXES_INCIDENT_PACKAGE
    ]
    installed_version = installed_packages.get(HYPRLAND_FIXES_INCIDENT_PACKAGE, "")
    pending = set(pending_package_names or ())
    cache_names = set(helper_cache_names or ())
    if incident_records:
        return [SecurityFinding(
            rule_id="SEC-AUR-HYPRLAND-FIXES-HISTORY",
            severity=Severity.CRITICAL,
            category="aur_campaign",
            title="Pacman history records a hyprland-fixes package transaction.",
            summary="AuraScan found a bounded package-manager transaction for the exact package reported with a root remote-access payload.",
            why_it_matters="The malicious source history predates the public report. Package history cannot prove that its payload completed, but uninstalling the package would not establish that the host is clean.",
            recommended_action="Disconnect the host, preserve evidence, and investigate from trusted recovery media. Revoke unexpected Tailscale nodes/keys and rotate credentials from a separate clean device.",
            package_name=HYPRLAND_FIXES_INCIDENT_PACKAGE,
            evidence=[
                f"{record.action}={record.package} {record.version} at {record.timestamp}"
                for record in incident_records[:8]
            ] + [
                f"reference={HYPRLAND_FIXES_INCIDENT_REFERENCE}",
                f"source_commit={HYPRLAND_FIXES_SOURCE_COMMIT_REFERENCE}",
            ],
            confidence="high",
            source="arch-aur-general",
        )]
    if installed_version:
        return [SecurityFinding(
            rule_id="SEC-AUR-HYPRLAND-FIXES-INSTALLED",
            severity=Severity.HIGH,
            category="aur_campaign",
            title="The reported hyprland-fixes package is installed.",
            summary="The installed package name matches the package reported for a Tailscale and root-SSH backdoor.",
            why_it_matters="A name match alone cannot prove which revision ran, but this package should be treated as a potential host compromise until local artifacts are investigated.",
            recommended_action="Do not run the package. Preserve package history and inspect the host from trusted recovery media before deciding on remediation.",
            package_name=HYPRLAND_FIXES_INCIDENT_PACKAGE,
            evidence=[
                f"installed={HYPRLAND_FIXES_INCIDENT_PACKAGE} {installed_version}",
                f"reference={HYPRLAND_FIXES_INCIDENT_REFERENCE}",
            ],
            confidence="medium",
            source="arch-aur-general",
        )]
    if HYPRLAND_FIXES_INCIDENT_PACKAGE in pending:
        return [SecurityFinding(
            rule_id="SEC-AUR-HYPRLAND-FIXES-PENDING",
            severity=Severity.HIGH,
            category="aur_campaign",
            title="A pending package matches the reported hyprland-fixes backdoor.",
            summary="The pending package name is the package removed after the 28 August 2026 root remote-access report.",
            why_it_matters="A package-name match is not proof that identical source content is pending, but this name requires fresh static and source review before any build.",
            recommended_action="Do not build the pending revision. Preserve its PKGBUILD, install hook, source URL, and commit metadata for review.",
            package_name=HYPRLAND_FIXES_INCIDENT_PACKAGE,
            evidence=[
                f"pending={HYPRLAND_FIXES_INCIDENT_PACKAGE}",
                f"reference={HYPRLAND_FIXES_INCIDENT_REFERENCE}",
            ],
            confidence="medium",
            source="arch-aur-general",
        )]
    if HYPRLAND_FIXES_INCIDENT_PACKAGE in cache_names:
        return [SecurityFinding(
            rule_id="SEC-AUR-HYPRLAND-FIXES-HELPER-CACHE",
            severity=Severity.LOW,
            category="aur_campaign",
            title="An AUR helper cache contains hyprland-fixes.",
            summary="A matching package directory remains in a bounded helper-cache scan.",
            why_it_matters="A cache entry indicates retrieval, not installation or execution, but can preserve useful package provenance.",
            recommended_action="Preserve and inspect the cached Git history and files as inert evidence; do not execute them.",
            package_name=HYPRLAND_FIXES_INCIDENT_PACKAGE,
            evidence=[
                f"cached={HYPRLAND_FIXES_INCIDENT_PACKAGE}",
                f"reference={HYPRLAND_FIXES_INCIDENT_REFERENCE}",
            ],
            confidence="low",
            source="arch-aur-general",
        )]
    return []


def _host_indicator_path_without_symlinks(root: Path, logical_path: str) -> Optional[Path]:
    """Return an injected-root path only when no existing component is a symlink."""

    candidate = root
    try:
        if candidate.is_symlink():
            return None
        for part in Path(logical_path.lstrip("/")).parts:
            candidate = candidate / part
            if candidate.is_symlink():
                return None
    except OSError:
        return None
    return candidate


def _read_host_indicator_text(root: Path, logical_path: str) -> str:
    path = _host_indicator_path_without_symlinks(root, logical_path)
    if path is None:
        return ""
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_HOST_INDICATOR_BYTES:
            return ""
        with path.open("rb") as handle:
            payload = handle.read(MAX_HOST_INDICATOR_BYTES + 1)
        if len(payload) > MAX_HOST_INDICATOR_BYTES:
            return ""
        return payload.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _existing_hyprland_fixes_artifacts(root: Path) -> List[str]:
    existing: List[str] = []
    for logical_path in HYPRLAND_FIXES_ARTIFACT_PATHS:
        path = _host_indicator_path_without_symlinks(root, logical_path)
        if path is None:
            continue
        try:
            if path.is_file():
                existing.append(logical_path)
        except OSError:
            continue
    return existing


def _hyprland_fixes_content_markers(root: Path) -> List[str]:
    markers: List[str] = []
    for logical_path in (
        "/etc/pacman.d/mirrorlist-criteria",
        "/etc/pacman.d/keyring-syncer",
    ):
        text = _read_host_indicator_text(root, logical_path)
        if re.search(r"(?im)^\s*Port\s+(?:3333|4444)\s*$", text) and re.search(
            r"(?im)^\s*PermitRootLogin\s+yes\s*$", text
        ):
            markers.append(f"root-sshd-config={logical_path}")

    for logical_path in (
        "/usr/lib/systemd/system/arch-mirrorlist-criteria.service",
        "/etc/systemd/system/arch-keyring-syncer.service",
    ):
        text = _read_host_indicator_text(root, logical_path)
        if re.search(r"/usr/sbin/sshd\s+-D\s+-f\s+/etc/pacman\.d/", text, re.IGNORECASE):
            markers.append(f"disguised-sshd-service={logical_path}")

    timer_text = _read_host_indicator_text(root, "/etc/systemd/system/hyprland-fixes.timer")
    if re.search(r"(?im)^\s*OnCalendar\s*=\s*hourly\s*$", timer_text):
        markers.append("hourly-persistence=/etc/systemd/system/hyprland-fixes.timer")

    sudoers_text = _read_host_indicator_text(root, "/etc/sudoers.d/hyprland-fixes-permissions")
    if "NOPASSWD:" in sudoers_text and "/usr/bin/hyprland-fixes" in sudoers_text:
        markers.append("passwordless-sudo=/etc/sudoers.d/hyprland-fixes-permissions")

    key_locations: Dict[str, List[str]] = {}
    for logical_path in ("/etc/userkeys", "/etc/system-functions", "/root/pamkeys"):
        text = _read_host_indicator_text(root, logical_path)
        match = re.search(r"(?m)^\s*(ssh-ed25519\s+[A-Za-z0-9+/=]+)(?:\s|$)", text)
        if not match:
            continue
        digest = hashlib.sha256(match.group(1).encode("utf-8")).hexdigest()
        key_locations.setdefault(digest, []).append(logical_path)
    duplicate_key_paths = max(key_locations.values(), key=len, default=[])
    if len(duplicate_key_paths) >= 2:
        markers.append("duplicated-root-ssh-key=" + ",".join(sorted(duplicate_key_paths)))

    suid_paths: List[str] = []
    for logical_path in (
        "/etc/hyprland-fixes",
        "/usr/lib/hyprland-fixes",
        "/usr/bin/hyprland-fixes",
        "/etc/arch-mirror-sync",
        "/usr/lib/arch-mirror-sync",
        "/usr/local/bin/arch-mirror-sync",
    ):
        path = _host_indicator_path_without_symlinks(root, logical_path)
        if path is None:
            continue
        try:
            metadata = path.stat()
            if stat.S_ISREG(metadata.st_mode) and metadata.st_mode & stat.S_ISUID:
                suid_paths.append(logical_path)
        except OSError:
            continue
    if suid_paths:
        markers.append("suid-payload=" + ",".join(suid_paths))

    for logical_path in ("/etc/ufw/user.rules", "/etc/ufw/user6.rules"):
        text = _read_host_indicator_text(root, logical_path)
        if HYPRLAND_FIXES_TAILSCALE_PEER in text:
            markers.append(f"reported-tailscale-peer-firewall-rule={logical_path}")

    for logical_path in ("/etc/hyprland-fixes", "/usr/lib/hyprland-fixes", "/usr/bin/hyprland-fixes"):
        text = _read_host_indicator_text(root, logical_path)
        behavior_count = sum((
            bool(re.search(r"\btailscale\s+up\b[^\n]*--auth-?key", text, re.IGNORECASE)),
            bool(re.search(r"\bsshd\b[^\n]*-f\s+/etc/pacman\.d/", text, re.IGNORECASE)),
            bool(re.search(r"\bjournalctl\b[^\n]*--vacuum-time\s*=\s*1s\b", text, re.IGNORECASE)),
            bool(re.search(r"\bchmod\s+0?4[0-7]{3}\b", text, re.IGNORECASE)),
        ))
        if behavior_count >= 2:
            markers.append(f"backdoor-behavior={logical_path}")
    return markers


def detect_host_campaign_indicators(root: Path = Path("/")) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    artifacts = _existing_hyprland_fixes_artifacts(root)
    markers = _hyprland_fixes_content_markers(root)
    strong_markers = [
        marker for marker in markers
        if not marker.startswith("reported-tailscale-peer-firewall-rule=")
    ]
    if artifacts or strong_markers:
        severity = Severity.CRITICAL if len(artifacts) >= 2 or strong_markers else Severity.HIGH
        supporting_marker_count = len(markers) - len(strong_markers)
        findings.append(SecurityFinding(
            rule_id="SEC-AUR-HYPRLAND-FIXES-HOST-ARTIFACTS",
            severity=severity,
            category="aur_campaign",
            title="Artifacts associated with the hyprland-fixes backdoor are present.",
            summary=(
                f"AuraScan found {len(artifacts)} reported path artifact(s), "
                f"{len(strong_markers)} validated behavior marker(s), and "
                f"{supporting_marker_count} supporting peer reference(s) under the selected root."
            ),
            why_it_matters="The reported artifact set was used for root SSH access, privilege persistence, or attacker-network access; a normal tailscaled service or matching Tailscale-range address by itself does not trigger this finding.",
            recommended_action="Disconnect the host and preserve evidence. Investigate from trusted recovery media; do not execute or merely delete the reported files on the live system.",
            package_name=HYPRLAND_FIXES_INCIDENT_PACKAGE,
            evidence=[f"artifact={path}" for path in artifacts[:16]] + markers[:16],
            confidence="high" if severity == Severity.CRITICAL else "medium",
            source="deterministic-host-indicators",
        ))
    bpf_marker_names: List[str] = []
    bpf_root = _host_indicator_path_without_symlinks(root, "/sys/fs/bpf")
    if bpf_root is not None:
        try:
            with os.scandir(bpf_root) as entries:
                for entry_count, entry in enumerate(entries, 1):
                    if entry_count > MAX_HOST_INDICATOR_ENTRIES:
                        break
                    if entry.name.startswith("hidden_") and not entry.is_symlink():
                        bpf_marker_names.append(entry.name)
                        if len(bpf_marker_names) >= 16:
                            break
        except OSError:
            bpf_marker_names = []
    if bpf_marker_names:
        findings.append(SecurityFinding(
            rule_id="SEC-AUR-CAMPAIGN-BPF-PERSISTENCE",
            severity=Severity.CRITICAL,
            category="aur_campaign",
            title="A campaign-associated eBPF persistence marker exists.",
            summary=f"AuraScan found {len(bpf_marker_names)} hidden_* object(s) under /sys/fs/bpf.",
            why_it_matters="This is stronger host evidence than a package-name match and may indicate active persistence.",
            recommended_action="Disconnect the host and investigate from trusted recovery media; do not rely on package removal alone.",
            evidence=bpf_marker_names,
            confidence="high",
        ))
    return findings


def run_arch_audit(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    root: Path = Path("/"),
    offline: bool = False,
) -> ArchAuditResult:
    if offline:
        return ArchAuditResult(status="skipped_offline")
    executable = which("arch-audit")
    if not executable:
        return ArchAuditResult(status="not_installed")
    command = [executable, "--json"]
    if root != Path("/"):
        command.extend(["--dbpath", str(root / "var/lib/pacman")])
    try:
        result = _run_capture(runner, command, timeout=45)
    except subprocess.TimeoutExpired:
        return ArchAuditResult(status="timeout", error="arch-audit exceeded 45 seconds", command=command)
    except (OSError, subprocess.SubprocessError) as exc:
        return ArchAuditResult(status="error", error=str(exc), command=command)
    if int(getattr(result, "returncode", 0)) != 0:
        error = str(getattr(result, "stderr", "") or "arch-audit failed").strip()
        return ArchAuditResult(status="error", error=error[:500], command=command)
    try:
        payload = json.loads(str(getattr(result, "stdout", "") or ""))
        findings = parse_arch_audit_json(payload)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return ArchAuditResult(status="invalid_output", error=str(exc), command=command)
    return ArchAuditResult(status="ok", findings=findings, command=command)


def parse_arch_audit_json(payload: object) -> List[SecurityFinding]:
    if not isinstance(payload, list):
        raise ValueError("arch-audit JSON must be an array")
    findings: List[SecurityFinding] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"arch-audit item {index} is not an object")
        packages = item.get("packages")
        issues = item.get("issues")
        if not isinstance(packages, list) or not all(isinstance(name, str) for name in packages):
            raise ValueError(f"arch-audit item {index} has invalid packages")
        if not isinstance(issues, list) or not all(isinstance(issue, str) for issue in issues):
            raise ValueError(f"arch-audit item {index} has invalid issues")
        severity = _arch_audit_severity(str(item.get("severity") or "Unknown"))
        status = str(item.get("status") or "Unknown")
        fixed = str(item.get("fixed") or "")
        advisory = str(item.get("name") or "unknown advisory")
        kind = str(item.get("type") or "unknown")
        for package in packages:
            if not PACKAGE_NAME_RE.fullmatch(package):
                continue
            fix_text = f" Upgrade to {fixed} or newer." if fixed else ""
            findings.append(SecurityFinding(
                rule_id="SEC-ARCH-AUDIT-" + re.sub(r"[^A-Za-z0-9]+", "-", advisory).strip("-").upper(),
                severity=severity,
                category="official_vulnerability",
                title=f"{package} has an Arch security advisory.",
                summary=f"{advisory} reports {status.lower()} {kind} risk for this installed package.{fix_text}",
                why_it_matters="This advisory comes from the Arch Security Team data used by arch-audit, not from the AUR campaign list.",
                recommended_action=(
                    f"Install the signed repository version {fixed} or newer."
                    if fixed
                    else "Follow the Arch security advisory and update when a fixed signed package becomes available."
                ),
                package_name=package,
                evidence=[advisory] + issues[:16] + ([f"fixed={fixed}"] if fixed else []),
                confidence="high",
                source="arch-audit",
            ))
    return findings


def _arch_audit_severity(value: str) -> Severity:
    normalized = value.strip().upper()
    if normalized in Severity.__members__:
        return Severity[normalized]
    return Severity.MEDIUM


def audit_campaign_exposure(
    campaign: CampaignIntel,
    installed_packages: Mapping[str, str],
    history: Sequence[PacmanHistoryRecord],
    *,
    pending_package_names: Optional[Iterable[str]] = None,
    helper_cache_names: Optional[Iterable[str]] = None,
) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    pending = set(pending_package_names or ())
    cache_names = set(helper_cache_names or ())
    in_window: Dict[str, List[PacmanHistoryRecord]] = {}
    for record in history:
        event_date = record.event_date
        if (
            record.package in campaign.package_names
            and event_date is not None
            and campaign.window_start <= event_date <= campaign.window_end
        ):
            in_window.setdefault(record.package, []).append(record)

    all_names = sorted((set(installed_packages) | pending | cache_names) & campaign.package_names)
    historical_names = sorted(in_window)
    for name in sorted(set(all_names) | set(historical_names)):
        records = in_window.get(name, [])
        if records:
            findings.append(SecurityFinding(
                rule_id="SEC-AUR-CAMPAIGN-HISTORY-WINDOW",
                severity=Severity.CRITICAL,
                category="aur_campaign",
                title=f"Pacman recorded a {name} transaction during the AUR campaign window.",
                summary=(
                    f"Pacman history contains {len(records)} matching event(s) between "
                    f"{campaign.window_start.isoformat()} and {campaign.window_end.isoformat()}."
                ),
                why_it_matters="The package name and transaction timing overlap the known campaign, creating credible exposure evidence even though the exact malicious commit is not proven. A later removal does not undo prior host changes.",
                recommended_action="Disconnect the host, preserve the report, rotate credentials from a clean device, and investigate from trusted recovery media.",
                package_name=name,
                evidence=[
                    f"{record.timestamp} {record.action} {record.package} ({record.version})"
                    for record in records[:12]
                ],
                confidence="high",
            ))
            continue
        if name in installed_packages:
            installed_version = str(installed_packages[name] or "")
            version_sentence = (
                f" The installed version is {installed_version}."
                if installed_version and "not collected" not in installed_version
                else ""
            )
            findings.append(SecurityFinding(
                rule_id="SEC-AUR-CAMPAIGN-INSTALLED-NAME",
                severity=Severity.MEDIUM,
                category="aur_campaign",
                title=f"{name} appears in the historical AUR campaign list.",
                summary=(
                    "The currently installed package name matches the community-maintained list."
                    + version_sentence
                ),
                why_it_matters="The package may have been installed before, during, or after cleanup, so a name-only match needs correlation rather than panic.",
                recommended_action="Inspect its AUR Git history and build provenance; do not assume that removing the package would clean an already compromised host.",
                package_name=name,
                evidence=[
                    f"installed={name}" + (f" {installed_version}" if installed_version else ""),
                    f"campaign={campaign.campaign_id}",
                ],
                confidence="medium",
            ))
        elif name in pending:
            findings.append(SecurityFinding(
                rule_id="SEC-AUR-CAMPAIGN-PENDING-NAME",
                severity=Severity.MEDIUM,
                category="aur_campaign",
                title=f"Pending AUR package {name} appeared in the historical campaign.",
                summary="The package name is present in the campaign list, but AuraScan has not proven that the current AUR commit is malicious.",
                why_it_matters="Packages were cleaned and may now be legitimate, while another malicious commit could also exist.",
                recommended_action="Require a fresh PKGBUILD/install-hook scan and review the AUR commit history before building.",
                package_name=name,
                evidence=[f"pending={name}", f"campaign={campaign.campaign_id}"],
                confidence="medium",
            ))
        elif name in cache_names:
            findings.append(SecurityFinding(
                rule_id="SEC-AUR-CAMPAIGN-HELPER-CACHE",
                severity=Severity.LOW,
                category="aur_campaign",
                title=f"An AUR helper cache contains {name}.",
                summary="A matching package directory remains in a bounded AUR helper cache scan.",
                why_it_matters="A cache entry indicates retrieval, not installation or execution, but can help reconstruct provenance.",
                recommended_action="Inspect the cached Git history and PKGBUILD before deleting evidence.",
                package_name=name,
                evidence=[f"cached={name}", f"campaign={campaign.campaign_id}"],
                confidence="low",
            ))
    return findings


def build_security_audit(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    root: Path = Path("/"),
    home: Optional[Path] = None,
    state_root: Optional[Path] = None,
    manifest_path: Optional[Path] = None,
    package_list_path: Optional[Path] = None,
    installed_packages: Optional[Mapping[str, str]] = None,
    pending_package_names: Optional[Iterable[str]] = None,
    log_paths: Optional[Iterable[Path]] = None,
    refresh: bool = False,
    offline: bool = False,
    include_arch_audit: bool = True,
    include_host_indicators: bool = True,
    urlopen: Callable = urllib_urlopen,
) -> SecurityAuditReport:
    notes: List[str] = []
    try:
        campaign, load_notes = load_campaign_intel(
            manifest_path=manifest_path,
            package_list_path=package_list_path,
            state_root=state_root,
        )
        notes.extend(load_notes)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        campaign = None
        notes.append(f"Campaign intelligence could not be loaded: {exc}")

    if refresh and offline:
        notes.append("Campaign refresh was skipped because offline mode is enabled.")
    elif refresh and campaign is not None:
        try:
            campaign = refresh_campaign_intel(campaign, state_root=state_root, urlopen=urlopen)
        except (OSError, UnicodeError, ValueError, HTTPError, URLError) as exc:
            notes.append(f"Campaign refresh failed; retained validated {campaign.data_origin} data: {exc}")

    if installed_packages is None:
        installed, package_error = collect_installed_packages(runner=runner, root=root)
        if package_error:
            notes.append(f"Installed package query failed: {package_error}")
    else:
        installed = dict(installed_packages)

    history, history_truncated, history_notes = collect_pacman_history(root=root, log_paths=log_paths)
    notes.extend(history_notes)
    cache_scan_names = set(campaign.package_names) if campaign else set()
    cache_scan_names.add(HYPRLAND_FIXES_INCIDENT_PACKAGE)
    cache_matches, cache_count, cache_truncated = scan_helper_cache_names(home, cache_scan_names)
    if cache_truncated:
        notes.append(f"AUR helper cache scan stopped after {MAX_CACHE_ENTRIES} entries.")

    campaign_findings: List[SecurityFinding] = []
    campaign_findings.extend(audit_hyprland_fixes_exposure(
        installed,
        history,
        pending_package_names=pending_package_names,
        helper_cache_names=cache_matches,
    ))
    if campaign is not None:
        campaign_findings.extend(audit_campaign_exposure(
            campaign,
            installed,
            history,
            pending_package_names=pending_package_names,
            helper_cache_names=cache_matches,
        ))
    if include_host_indicators:
        campaign_findings.extend(detect_host_campaign_indicators(root))

    if include_arch_audit:
        arch_result = run_arch_audit(runner=runner, which=which, root=root, offline=offline)
    else:
        arch_result = ArchAuditResult(status="disabled")
    if arch_result.status == "not_installed":
        notes.append("Install arch-audit to include official Arch Security Team CVE advisories.")
    elif arch_result.status not in {"ok", "disabled", "skipped_offline"} and arch_result.error:
        notes.append(f"arch-audit did not complete: {arch_result.error}")

    findings = campaign_findings + list(arch_result.findings)
    status = "ok"
    if campaign is None:
        status = "partial" if arch_result.status == "ok" else "unavailable"
    elif arch_result.status not in {"ok", "disabled"}:
        status = "partial"
    return SecurityAuditReport(
        campaign=campaign,
        findings=findings,
        arch_audit=arch_result,
        installed_package_count=len(installed),
        history_record_count=len(history),
        helper_cache_entry_count=cache_count,
        history_truncated=history_truncated,
        notes=notes,
        status=status,
    )


def bundled_campaign_doctor_status(
    *,
    manifest_path: Optional[Path] = None,
    package_list_path: Optional[Path] = None,
) -> Dict[str, object]:
    try:
        campaign, _notes = load_campaign_intel(
            manifest_path=manifest_path,
            package_list_path=package_list_path,
            state_root=Path("/nonexistent/aurascan-security-intel"),
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {"ready": False, "error": str(exc)}
    return {
        "ready": True,
        "campaign_id": campaign.campaign_id,
        "package_count": len(campaign.package_names),
        "sha256": campaign.sha256,
        "retrieved_at": campaign.retrieved_at,
        "source_kind": campaign.source_kind,
    }


def build_security_audit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan security-audit",
        description="Check installed packages and pacman history against bounded AUR campaign intelligence and optional Arch security advisories.",
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit a structured JSON report")
    parser.add_argument("--verbose", action="store_true", help="show every finding and bounded evidence")
    parser.add_argument("--refresh", action="store_true", help="refresh the plain-text campaign list over HTTPS before scanning")
    parser.add_argument("--offline", action="store_true", help="use packaged/cached campaign data and skip arch-audit network access")
    parser.add_argument("--no-arch-audit", action="store_true", help="skip optional official-package CVE checks")
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    parser.add_argument("--home", type=Path, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--state-root", type=Path, default=None, help=argparse.SUPPRESS)
    return parser


def run_security_audit(
    argv: Optional[Sequence[str]] = None,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    stdout=None,
    stderr=None,
    urlopen: Callable = urllib_urlopen,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_security_audit_parser().parse_args(list(argv or []))
    home = args.home
    if home is None and args.root == Path("/"):
        home = Path.home()
    if not args.json_output:
        print("[AuraScan] Checking known AUR campaign exposure and official package advisories...", file=stdout)
    report = build_security_audit(
        runner=runner,
        which=which,
        root=args.root,
        home=home,
        state_root=args.state_root,
        refresh=bool(args.refresh),
        offline=bool(args.offline),
        include_arch_audit=not bool(args.no_arch_audit),
        urlopen=urlopen,
    )
    if args.json_output:
        print(report.to_json(), file=stdout)
    else:
        print(report.render_terminal(verbose=bool(args.verbose)), file=stdout)
    if report.status == "unavailable":
        print("[AuraScan] Security audit was unavailable.", file=stderr)
        return EXIT_SECURITY_AUDIT_UNAVAILABLE
    return EXIT_SECURITY_ALERT if report.has_alert else 0
