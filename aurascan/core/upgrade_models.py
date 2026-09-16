"""Inert upgrade values: observed system state and planned upgrade state.

These are the data shapes the upgrade subsystem reasons about: the packages a
transaction would touch, the foreign-package metadata that constrains it, the
plan itself, and the observed system state a plan is evaluated against. Incident
collection and the kernel-module check consume the same shapes, which is why they
live below every workflow instead of inside the upgrade workflow.

Everything here is inert: dataclass fields, ``to_dict`` projections, the
``available``/``package_names`` helpers and nothing else. Collecting a snapshot
reads the machine and therefore stays in the workflow
(``upgrade_preflight.collect_system_snapshot``); the captured trusted-executable
identities a plan carries are referenced by type only, never run.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover - annotations only, never executed
    from aurascan.core.trusted_executable import TrustedExecutable


@dataclass
class UpgradePackage:
    name: str
    new_version: str = ""
    old_version: str = ""
    repo: str = ""
    package_type: str = "repo"
    size: str = ""
    depends: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    replaces: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "repo": self.repo,
            "package_type": self.package_type,
            "size": self.size,
            "depends": list(self.depends),
            "conflicts": list(self.conflicts),
            "replaces": list(self.replaces),
        }


@dataclass
class ForeignPackageInfo:
    name: str
    version: str = ""
    depends: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    missing_depends: List[str] = field(default_factory=list)
    install_script: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "depends": list(self.depends),
            "provides": list(self.provides),
            "conflicts": list(self.conflicts),
            "missing_depends": list(self.missing_depends),
            "install_script": self.install_script,
        }


@dataclass
class UpgradePlan:
    repo_packages: List[UpgradePackage] = field(default_factory=list)
    aur_packages: List[UpgradePackage] = field(default_factory=list)
    removals: List[str] = field(default_factory=list)
    replacements: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    selected_helper: str = "none"
    helper_error: str = ""
    preview_error: str = ""
    preview_command: List[str] = field(default_factory=list)
    final_command: List[str] = field(default_factory=list)
    command_source: str = "pacman"
    trusted_executables: Dict[str, "TrustedExecutable"] = field(default_factory=dict, repr=False)

    @property
    def available(self) -> bool:
        return not self.preview_error

    def package_names(self) -> List[str]:
        return [pkg.name for pkg in self.repo_packages + self.aur_packages]

    def to_dict(self) -> Dict[str, object]:
        return {
            "repo_packages": [pkg.to_dict() for pkg in self.repo_packages],
            "aur_packages": [pkg.to_dict() for pkg in self.aur_packages],
            "removals": list(self.removals),
            "replacements": list(self.replacements),
            "conflicts": list(self.conflicts),
            "selected_helper": self.selected_helper,
            "helper_error": self.helper_error,
            "preview_error": self.preview_error,
            "preview_command": list(self.preview_command),
            "final_command": list(self.final_command),
            "command_source": self.command_source,
            "trusted_executables": {
                name: executable.to_dict()
                for name, executable in sorted(self.trusted_executables.items())
            },
        }


@dataclass
class SystemSnapshot:
    running_kernel: str = ""
    distro_info: Dict[str, object] = field(default_factory=dict)
    installed_packages: List[str] = field(default_factory=list)
    foreign_packages: List[str] = field(default_factory=list)
    foreign_package_info: List[ForeignPackageInfo] = field(default_factory=list)
    package_info: List[ForeignPackageInfo] = field(default_factory=list)
    ignored_packages: List[str] = field(default_factory=list)
    ignored_groups: List[str] = field(default_factory=list)
    root_free_mib: Optional[int] = None
    boot_free_mib: Optional[int] = None
    boot_paths: List[str] = field(default_factory=list)
    dkms_packages: List[str] = field(default_factory=list)
    nvidia_packages: List[str] = field(default_factory=list)
    zfs_packages: List[str] = field(default_factory=list)
    virtualbox_packages: List[str] = field(default_factory=list)
    pacnew_count: int = 0
    pacsave_count: int = 0
    pacnew_scan_truncated: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "running_kernel": self.running_kernel,
            "distro": dict(self.distro_info),
            "installed_package_count": len(self.installed_packages),
            "foreign_packages": list(self.foreign_packages),
            "foreign_package_info": [item.to_dict() for item in self.foreign_package_info],
            "package_info": [item.to_dict() for item in self.package_info],
            "ignored_packages": list(self.ignored_packages),
            "ignored_groups": list(self.ignored_groups),
            "root_free_mib": self.root_free_mib,
            "boot_free_mib": self.boot_free_mib,
            "boot_paths": list(self.boot_paths),
            "dkms_packages": list(self.dkms_packages),
            "nvidia_packages": list(self.nvidia_packages),
            "zfs_packages": list(self.zfs_packages),
            "virtualbox_packages": list(self.virtualbox_packages),
            "pacnew_count": self.pacnew_count,
            "pacsave_count": self.pacsave_count,
            "pacnew_scan_truncated": self.pacnew_scan_truncated,
        }
