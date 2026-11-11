"""Opt-in isolated AUR build backend.

A reviewed package build is executed inside a fresh copy of a devtools
``extra-x86_64`` chroot instead of on the daily system. The build still runs
real package code, so this module is a risk-reduction boundary: it keeps the
build away from the caller's home, credentials, and AuraScan state, and it
produces bounded, hash-bound artifacts for a second scan before installation.
It is not a kernel-isolation guarantee, not proof that a package is safe, and
not a substitute for the deterministic scan that authorizes the build.

Only fixed, root-owned system tools are used. No shell is involved, the build
directory is copied out of the reviewed checkout, the environment is reduced
to fixed values, and the work tree is removed after the caller has scanned and
installed the artifacts.
"""

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence, TextIO, Tuple

from aurascan.core.trusted_tools import (
    TrustedTool,
    TrustedToolError,
    capture_trusted_system_tool,
    revalidate_trusted_system_tool,
)


AUR_SANDBOX_ENV = "AURASCAN_AUR_SANDBOX"
AUR_SANDBOX_WORK_ROOT_ENV = "AURASCAN_AUR_SANDBOX_WORK_ROOT"
AUR_SANDBOX_BACKENDS = ("off", "devtools")
AUR_SANDBOX_DEFAULT_BACKEND = "devtools"
AUR_SANDBOX_BASE_ROOT = Path("/var/lib/archbuild")
AUR_SANDBOX_CHROOT_NAME = "extra-x86_64"
AUR_SANDBOX_DEFAULT_WORK_ROOT = Path("/var/tmp")
AUR_SANDBOX_BUILD_TIMEOUT_SECONDS = 3600.0
AUR_SANDBOX_MAX_TREE_ENTRIES = 20000
AUR_SANDBOX_MAX_TREE_BYTES = 4 * 1024 * 1024 * 1024
AUR_SANDBOX_MAX_ARTIFACTS = 16
AUR_SANDBOX_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024
AUR_SANDBOX_MAX_TOTAL_ARTIFACT_BYTES = 12 * 1024 * 1024 * 1024
AUR_SANDBOX_PRUNED_TREES = frozenset({'.git', '.hg', '.svn', 'src', 'pkg'})
AUR_SANDBOX_ARTIFACT_SUFFIXES = (
    ".pkg.tar.zst",
    ".pkg.tar.xz",
    ".pkg.tar.gz",
    ".pkg.tar.bz2",
    ".pkg.tar.lrz",
    ".pkg.tar.lzo",
    ".pkg.tar.Z",
    ".pkg.tar",
)
AUR_SANDBOX_REQUIRED_TOOLS = (
    "arch-nspawn",
    "mkarchroot",
    "systemd-nspawn",
)
AUR_SANDBOX_ROOT_COMMANDS = (
    "sudo",
    "cp",
    "rm",
)
AUR_SANDBOX_PACMAN_CONF = Path("/usr/share/devtools/pacman.conf.d/multilib.conf")
AUR_SANDBOX_MAKEPKG_CONF = Path("/usr/share/devtools/makepkg.conf.d/x86_64.conf")
AUR_SANDBOX_BUILD_SCRIPT = r'''set -eu
uid="$1"
gid="$2"
shift 2
sed -i -e '/^builduser:/d' /etc/passwd /etc/shadow /etc/group
mkdir -p /home/builduser
chown "$uid:$gid" /home/builduser
printf 'builduser:x:%s:\n' "$gid" >> /etc/group
printf 'builduser:x:%s:%s:builduser:/home/builduser:/bin/bash\n' "$uid" "$gid" >> /etc/passwd
printf 'builduser:!!:%s::::::\n' "$(( $(date -u +%s) / 86400 ))" >> /etc/shadow
printf 'builduser ALL=(root) NOPASSWD: /usr/bin/pacman\n' > /etc/sudoers.d/builduser-pacman
chmod 440 /etc/sudoers.d/builduser-pacman
chown -R "$uid:$gid" /build
exec sudo -H -u builduser --preserve-env=SOURCE_DATE_EPOCH,GNUPGHOME,SSH_AUTH_SOCK -- makepkg "$@"
'''
AUR_SANDBOX_PASSTHROUGH_MAKEPKG_ARGS = frozenset({
    "--syncdeps",
    "--nocheck",
    "--clean",
    "--cleanbuild",
    "--needed",
    "--force",
    "--noconfirm",
    "--noprogressbar",
})


class SandboxUnavailable(RuntimeError):
    """The configured sandbox cannot be used safely."""


class SandboxBuildError(RuntimeError):
    """The isolated build failed, timed out, or produced no usable artifact."""

    def __init__(self, message: str, *, retained_root: str = ""):
        super().__init__(message)
        self.retained_root = retained_root
        self.cleanup_warning = ""


@dataclass(frozen=True)
class SandboxConfig:
    backend: str = "off"
    work_root: Path = AUR_SANDBOX_DEFAULT_WORK_ROOT
    timeout_seconds: float = AUR_SANDBOX_BUILD_TIMEOUT_SECONDS
    error: str = ""

    @property
    def enabled(self) -> bool:
        return self.backend != "off"


@dataclass(frozen=True)
class SandboxToolIdentity:
    name: str
    path: str
    device: int
    inode: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "device": self.device,
            "inode": self.inode,
        }


@dataclass(frozen=True)
class SandboxStatus:
    enabled: bool
    available: bool
    backend: str
    reason: str = ""
    base_root: str = ""
    base_ready: bool = False
    tools: Tuple[SandboxToolIdentity, ...] = ()

    def to_dict(self) -> Dict[str, object]:
        return {
            "enabled": self.enabled,
            "available": self.available,
            "backend": self.backend,
            "reason": self.reason,
            "base_root": self.base_root,
            "base_ready": self.base_ready,
            "tools": [tool.to_dict() for tool in self.tools],
        }


@dataclass(frozen=True)
class SandboxArtifact:
    name: str
    path: str
    size: int
    sha256: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class SandboxBuildResult:
    backend: str
    build_root: Path
    artifacts: Tuple[SandboxArtifact, ...]
    duration_seconds: float
    started_at: float = 0.0
    command: Tuple[str, ...] = ()
    sudo_path: str = ""
    rm_path: str = ""
    sudo_tool: Optional[TrustedTool] = None
    rm_tool: Optional[TrustedTool] = None
    chroot_root: str = ""
    package_dir: str = ""


@dataclass(frozen=True)
class SandboxCleanupOutcome:
    """Observed result of one private build-tree removal attempt.

    ``removed`` reports the observed tree state, while ``verified`` is true
    only when the removal path completed cleanly. A completion status of zero
    is necessary but not sufficient: the tree must also be observed absent.
    """

    removed: bool
    verified: bool
    warning: str = ""
    exit_status: Optional[int] = None


def resolve_sandbox_config(env: Optional[Mapping[str, str]] = None) -> SandboxConfig:
    source = env if env is not None else os.environ
    raw = str(source.get(AUR_SANDBOX_ENV, "off") or "off").strip().lower()
    if raw in {"", "0", "false", "no"}:
        raw = "off"
    if raw in {"1", "true", "yes", "on"}:
        raw = AUR_SANDBOX_DEFAULT_BACKEND
    if raw not in AUR_SANDBOX_BACKENDS:
        return SandboxConfig(error=f"invalid {AUR_SANDBOX_ENV} value")
    work_root_raw = str(source.get(AUR_SANDBOX_WORK_ROOT_ENV, "") or "").strip()
    work_root = Path(work_root_raw) if work_root_raw else AUR_SANDBOX_DEFAULT_WORK_ROOT
    return SandboxConfig(backend=raw, work_root=work_root)


def sandbox_status(
    config: SandboxConfig,
    *,
    base_root: Path = AUR_SANDBOX_BASE_ROOT,
    tool_capture: Callable[..., Optional[TrustedTool]] = capture_trusted_system_tool,
    base_probe: Optional[Callable[[Path], Tuple[bool, str]]] = None,
    config_probe: Optional[Callable[[], Tuple[bool, str]]] = None,
) -> SandboxStatus:
    """Describe whether the configured backend can build right now.

    This only inspects fixed paths and tool identities. It never creates a
    chroot, executes a package manager, or starts a build.
    """

    if config.error:
        return SandboxStatus(
            enabled=False,
            available=False,
            backend=config.backend,
            reason=config.error,
        )
    if not config.enabled:
        return SandboxStatus(
            enabled=False,
            available=True,
            backend="off",
            reason="sandbox builds are disabled",
        )
    if config.backend != "devtools":
        return SandboxStatus(
            enabled=True,
            available=False,
            backend=config.backend,
            reason="unsupported sandbox backend",
        )

    identities = []
    for name in AUR_SANDBOX_REQUIRED_TOOLS + AUR_SANDBOX_ROOT_COMMANDS:
        try:
            tool = tool_capture(name)
        except (OSError, TypeError, TrustedToolError):
            return SandboxStatus(
                enabled=True,
                available=False,
                backend=config.backend,
                reason=f"the trusted {name} helper could not be validated",
            )
        if tool is None:
            return SandboxStatus(
                enabled=True,
                available=False,
                backend=config.backend,
                reason=f"the trusted {name} helper is not installed",
            )
        identities.append(SandboxToolIdentity(tool.name, tool.path, tool.device, tool.inode))

    config_ready, config_reason = (config_probe or _probe_config_paths)()
    if not config_ready:
        return SandboxStatus(
            enabled=True,
            available=False,
            backend=config.backend,
            reason=config_reason,
            tools=tuple(identities),
        )

    chroot = Path(base_root) / AUR_SANDBOX_CHROOT_NAME / "root"
    probe = base_probe or _probe_chroot_base
    ready, reason = probe(chroot)
    if not ready:
        return SandboxStatus(
            enabled=True,
            available=False,
            backend=config.backend,
            reason=reason,
            base_root=str(chroot),
            tools=tuple(identities),
        )

    return SandboxStatus(
        enabled=True,
        available=True,
        backend=config.backend,
        base_root=str(chroot),
        base_ready=True,
        tools=tuple(identities),
    )


def _probe_config_paths() -> Tuple[bool, str]:
    for path, label in (
        (AUR_SANDBOX_PACMAN_CONF, "devtools pacman configuration"),
        (AUR_SANDBOX_MAKEPKG_CONF, "devtools makepkg configuration"),
    ):
        if not _safe_root_owned_file(path):
            return False, f"the {label} is missing or unsafe"
    return True, ""


def _probe_chroot_base(chroot: Path) -> Tuple[bool, str]:
    setup = (
        "sudo /usr/bin/mkarchroot -C /usr/share/devtools/pacman.conf.d/multilib.conf "
        "-M /usr/share/devtools/makepkg.conf.d/x86_64.conf "
        f"{chroot} base-devel multilib-devel"
    )
    for path, label in (
        (chroot.parent, "devtools chroot base"),
        (chroot, "devtools chroot"),
    ):
        try:
            metadata = os.lstat(str(path))
        except OSError:
            return False, f"the {label} is missing; create it once with: {setup}"
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return False, f"the {label} is not a regular directory"
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            return False, f"the {label} is not root-owned with safe permissions"
    if not _safe_root_owned_file(chroot / ".arch-chroot"):
        return False, "the devtools chroot is not a complete Arch chroot"
    return True, ""


def _safe_root_owned_file(path: Path) -> bool:
    try:
        metadata = os.lstat(str(path))
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode):
        return False
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        return False
    return not os.access(str(path), os.W_OK)


def sandbox_makepkg_arguments(makepkg_args: Sequence[str]) -> Tuple[str, ...]:
    """Reduce caller arguments to the bounded set the isolated build accepts."""

    result = []
    for arg in makepkg_args:
        if arg == "--":
            continue
        if arg in {"--install", "-i"}:
            # Installation is a separate, post-scan host step.
            continue
        if arg in AUR_SANDBOX_PASSTHROUGH_MAKEPKG_ARGS:
            result.append(arg)
            continue
        raise SandboxBuildError(
            "the isolated build accepts only a bounded makepkg argument set"
        )
    for required in ("--syncdeps", "--noconfirm"):
        if required not in result:
            result.append(required)
    return tuple(result)


def build_in_sandbox(
    package_dir: Path,
    *,
    config: SandboxConfig,
    makepkg_args: Sequence[str] = (),
    runner: Callable[..., object] = subprocess.run,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
    environ: Optional[Mapping[str, str]] = None,
    base_root: Path = AUR_SANDBOX_BASE_ROOT,
    tool_capture: Callable[..., Optional[TrustedTool]] = capture_trusted_system_tool,
    tool_revalidate: Callable[[TrustedTool], None] = revalidate_trusted_system_tool,
    base_probe: Optional[Callable[[Path], Tuple[bool, str]]] = None,
    config_probe: Optional[Callable[[], Tuple[bool, str]]] = None,
) -> SandboxBuildResult:
    """Copy the reviewed checkout and build it inside the devtools chroot.

    The returned build root belongs to the caller, who must scan the listed
    artifacts and then remove ``build_root``. On failure cleanup is attempted;
    if the tree is retained or removal cannot be verified, the raised
    ``SandboxBuildError`` carries a truthful ``cleanup_warning``.
    """

    source = Path(package_dir)
    if config.error:
        raise SandboxUnavailable(config.error)
    if config.backend != "devtools":
        raise SandboxUnavailable("the isolated build backend is not enabled")
    status = sandbox_status(
        config,
        base_root=base_root,
        tool_capture=tool_capture,
        base_probe=base_probe,
        config_probe=config_probe,
    )
    if not status.available:
        raise SandboxUnavailable(status.reason or "the isolated build backend is unavailable")

    tools = {}
    for name in AUR_SANDBOX_REQUIRED_TOOLS + AUR_SANDBOX_ROOT_COMMANDS:
        try:
            tool = tool_capture(name)
            if tool is None:
                raise SandboxUnavailable(f"the trusted {name} helper is not installed")
            tool_revalidate(tool)
        except (OSError, TypeError, TrustedToolError) as exc:
            raise SandboxUnavailable(f"the trusted {name} helper could not be validated") from exc
        tools[name] = tool

    if not source.is_dir() or source.is_symlink():
        raise SandboxBuildError("the package directory is not a regular directory")
    pkgbuild = source / "PKGBUILD"
    try:
        pkgbuild_meta = os.lstat(str(pkgbuild))
    except OSError as exc:
        raise SandboxBuildError("the package directory has no readable PKGBUILD") from exc
    if not stat.S_ISREG(pkgbuild_meta.st_mode):
        raise SandboxBuildError("the package directory has no regular PKGBUILD")

    makepkg_arguments = sandbox_makepkg_arguments(makepkg_args)
    work_root = Path(config.work_root)
    try:
        work_root.mkdir(parents=True, exist_ok=True)
        build_root = Path(tempfile.mkdtemp(prefix="aurascan-devbuild-", dir=str(work_root)))
    except OSError as exc:
        raise SandboxBuildError("the isolated build work root is unavailable") from exc
    started_at = time.time()
    started = time.monotonic()
    try:
        os.chmod(str(build_root), 0o700)
        package_copy = build_root / "build"
        _copy_package_tree(source, package_copy)
        home = build_root / "home"
        tmp = build_root / "tmp"
        cache = build_root / "cache"
        home.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        cache.mkdir(mode=0o700)
        build_environment = _sandbox_environment(home=home, tmp=tmp, environ=environ)
        chroot_copy = build_root / "root"
        copy_command = [
            tools["sudo"].path,
            tools["cp"].path,
            "-a",
            "--reflink=auto",
            status.base_root,
            str(chroot_copy),
        ]
        copy_result = _run_root_command(
            copy_command,
            runner=runner,
            cwd=str(build_root),
            env=build_environment,
            timeout=300.0,
        )
        if copy_result != 0:
            raise SandboxBuildError(
                f"the private chroot copy failed with exit status {copy_result}"
            )
        command = [
            tools["sudo"].path,
            tools["arch-nspawn"].path,
            "-c", str(cache),
            "-C", str(AUR_SANDBOX_PACMAN_CONF),
            "-M", str(AUR_SANDBOX_MAKEPKG_CONF),
            str(chroot_copy),
            f"--bind={package_copy}:/build",
            "--chdir=/build",
            "--setenv=HOME=/root",
            "--setenv=TMPDIR=/tmp",
            "--setenv=LC_ALL=C",
            "--setenv=LANG=C",
            "--setenv=TZ=UTC",
            "/bin/bash",
            "-c",
            AUR_SANDBOX_BUILD_SCRIPT,
            "aurascan-sandbox",
            str(os.getuid()),
            str(os.getgid()),
            *makepkg_arguments,
        ]
        returncode = _run_root_command(
            command,
            runner=runner,
            cwd=str(package_copy),
            env=build_environment,
            timeout=config.timeout_seconds,
        )
        duration = time.monotonic() - started
        if returncode != 0:
            raise SandboxBuildError(
                f"the isolated build failed with exit status {returncode}"
            )
        artifacts = _capture_artifacts(package_copy, started)
        if not artifacts:
            raise SandboxBuildError(
                "the isolated build produced no fresh package archive"
            )
        return SandboxBuildResult(
            backend=config.backend,
            build_root=build_root,
            artifacts=tuple(artifacts),
            duration_seconds=duration,
            started_at=started_at,
            command=tuple(command),
            sudo_path=tools["sudo"].path,
            rm_path=tools["rm"].path,
            sudo_tool=tools["sudo"],
            rm_tool=tools["rm"],
            chroot_root=str(chroot_copy),
            package_dir=str(package_copy),
        )
    except Exception as exc:
        outcome = _remove_work_tree(
            build_root,
            work_root,
            tools.get("sudo"),
            tools.get("rm"),
            runner,
            tool_revalidate=tool_revalidate,
        )
        if outcome.warning and isinstance(exc, SandboxBuildError):
            exc.cleanup_warning = outcome.warning
        raise


def cleanup_sandbox_build(
    result: SandboxBuildResult,
    *,
    runner: Callable[..., object] = subprocess.run,
    tool_revalidate: Callable[[TrustedTool], None] = revalidate_trusted_system_tool,
) -> str:
    """Remove the private build tree; return a truthful warning when needed.

    The captured ``sudo_tool``/``rm_tool`` objects from the build are reused
    and revalidated immediately before the privileged command. A warning is
    returned when the tree remains, the command status is nonzero, the
    completion evidence is malformed, or removal otherwise cannot be verified.
    """

    root = Path(result.build_root)
    outcome = _remove_work_tree(
        root,
        root.parent,
        result.sudo_tool,
        result.rm_tool,
        runner,
        tool_revalidate=tool_revalidate,
    )
    return outcome.warning


def _run_root_command(
    command,
    *,
    runner: Callable[..., object],
    cwd: str,
    env: Dict[str, str],
    timeout: float,
) -> int:
    try:
        result = runner(
            command,
            cwd=cwd,
            env=env,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxBuildError("the isolated build exceeded its time bound") from exc
    except (OSError, TypeError) as exc:
        raise SandboxBuildError("the isolated build could not be started") from exc
    return int(getattr(result, "returncode", 1))


def _tree_present(root: Path) -> bool:
    """Report whether the tree entry still exists without following links."""

    return os.path.lexists(str(root))


def _unverified_cleanup_warning(root: Path, detail: str) -> SandboxCleanupOutcome:
    """Build a truthful outcome for a cleanup attempt that is not verified.

    The wording never promises the tree is intact after a failed or partial
    removal, and never demands manual removal of a tree observed absent.
    """

    if _tree_present(root):
        return SandboxCleanupOutcome(
            removed=False,
            verified=False,
            warning=(
                f"{detail}; the build tree may be partially removed. "
                "Remove any remaining files manually."
            ),
        )
    return SandboxCleanupOutcome(
        removed=True,
        verified=False,
        warning=(
            f"{detail}, but the build tree is no longer present; "
            "removal may have been partial."
        ),
    )


def _completed_status(completed) -> Optional[int]:
    """Return the integer completion status, or None for unusable evidence."""

    status = getattr(completed, "returncode", None)
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    return status


def _remove_work_tree(
    root: Path,
    work_root: Path,
    sudo_tool: Optional[TrustedTool],
    rm_tool: Optional[TrustedTool],
    runner: Callable[..., object],
    *,
    tool_revalidate: Callable[[TrustedTool], None] = revalidate_trusted_system_tool,
) -> SandboxCleanupOutcome:
    """Remove one private build tree, using the captured root tools if needed.

    Privileged removal never executes a stored path string. The capture-time
    tool identities must be revalidated immediately before the command; a
    missing or changed identity leaves the tree in place. The completed
    command's status and the observed tree state are both required before the
    removal counts as verified success.
    """

    if not _tree_present(root):
        return SandboxCleanupOutcome(removed=True, verified=True)
    try:
        resolved_root = root.resolve()
        resolved_parent = Path(work_root).resolve()
    except (OSError, RuntimeError):
        return SandboxCleanupOutcome(
            removed=False,
            verified=False,
            warning=(
                "The isolated build tree path could not be resolved and was not "
                "removed; inspect it manually."
            ),
        )
    if resolved_root.parent != resolved_parent or not resolved_root.name.startswith(
        "aurascan-devbuild-"
    ):
        return SandboxCleanupOutcome(
            removed=False,
            verified=False,
            warning=(
                "The isolated build tree did not match the private cleanup path "
                "policy and was not removed; inspect it manually."
            ),
        )
    if root.is_symlink():
        return SandboxCleanupOutcome(
            removed=False,
            verified=False,
            warning=(
                "The isolated build tree is a symbolic link and was not removed; "
                "inspect it manually."
            ),
        )
    try:
        shutil.rmtree(str(root))
    except OSError:
        if not _tree_present(root):
            return _unverified_cleanup_warning(
                root, "Local removal of the isolated build tree did not complete cleanly"
            )
    else:
        if not _tree_present(root):
            return SandboxCleanupOutcome(removed=True, verified=True)
    if sudo_tool is None or rm_tool is None:
        return _unverified_cleanup_warning(
            root,
            "The isolated build tree could not be removed because no captured "
            "privileged helper was available",
        )
    try:
        tool_revalidate(sudo_tool)
        tool_revalidate(rm_tool)
    except (OSError, TypeError, TrustedToolError):
        return _unverified_cleanup_warning(
            root,
            "The isolated build tree could not be removed because a privileged "
            "helper identity could not be revalidated",
        )
    try:
        completed = runner(
            [sudo_tool.path, rm_tool.path, "-rf", "--one-file-system", str(root)],
            check=False,
            timeout=300.0,
        )
    except subprocess.TimeoutExpired:
        return _unverified_cleanup_warning(
            root, "The privileged cleanup command timed out"
        )
    except (OSError, TypeError):
        return _unverified_cleanup_warning(
            root, "The privileged cleanup command could not be started"
        )
    status = _completed_status(completed)
    if status is None:
        return _unverified_cleanup_warning(
            root, "The privileged cleanup command did not report a usable exit status"
        )
    if status != 0:
        return _unverified_cleanup_warning(
            root,
            f"The privileged cleanup command failed with exit status {status}",
        )
    if _tree_present(root):
        return SandboxCleanupOutcome(
            removed=False,
            verified=False,
            warning=(
                "The privileged cleanup command reported success, but the build "
                "tree is still present; remove it manually."
            ),
            exit_status=status,
        )
    return SandboxCleanupOutcome(removed=True, verified=True, exit_status=status)


def _sandbox_environment(
    *,
    home: Path,
    tmp: Path,
    environ: Optional[Mapping[str, str]],
) -> Dict[str, str]:
    source = environ if environ is not None else os.environ
    keep = ("USER", "LOGNAME")
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "TERM": str(source.get("TERM", "dumb")),
    }
    for name in keep:
        value = str(source.get(name, "") or "").strip()
        if value:
            env[name] = value
    return env


def _copy_package_tree(source: Path, destination: Path) -> None:
    """Copy the reviewed checkout without following links or special files."""

    entries = 0
    total_bytes = 0
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise SandboxBuildError("the isolated build directory could not be created") from exc
    for current, dirnames, filenames in os.walk(str(source), followlinks=False):
        current_path = Path(current)
        dirnames[:] = sorted(name for name in dirnames if name not in AUR_SANDBOX_PRUNED_TREES)
        relative = current_path.relative_to(source)
        target_dir = destination / relative
        if relative != Path("."):
            try:
                target_dir.mkdir(mode=0o700)
            except OSError as exc:
                raise SandboxBuildError("the isolated build directory could not be created") from exc
        for name in list(dirnames):
            child = current_path / name
            entries += 1
            if entries > AUR_SANDBOX_MAX_TREE_ENTRIES:
                raise SandboxBuildError("the package directory exceeds the entry bound")
            if os.path.islink(str(child)):
                raise SandboxBuildError("the package directory contains a linked directory")
            metadata = os.lstat(str(child))
            if not stat.S_ISDIR(metadata.st_mode):
                raise SandboxBuildError("the package directory contains an unsupported entry")
        for name in filenames:
            child = current_path / name
            entries += 1
            if entries > AUR_SANDBOX_MAX_TREE_ENTRIES:
                raise SandboxBuildError("the package directory exceeds the entry bound")
            target = target_dir / name
            metadata = os.lstat(str(child))
            if stat.S_ISLNK(metadata.st_mode):
                link = os.readlink(str(child))
                if os.path.isabs(link) or ".." in Path(link).parts:
                    raise SandboxBuildError("the package directory contains an escaping link")
                try:
                    os.symlink(link, str(target))
                except OSError as exc:
                    raise SandboxBuildError("the package directory link could not be copied") from exc
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise SandboxBuildError("the package directory contains an unsupported file")
            total_bytes += int(metadata.st_size)
            if total_bytes > AUR_SANDBOX_MAX_TREE_BYTES:
                raise SandboxBuildError("the package directory exceeds the byte bound")
            try:
                shutil.copy2(str(child), str(target), follow_symlinks=False)
            except OSError as exc:
                raise SandboxBuildError("the package directory could not be copied") from exc


def _capture_artifacts(build_dir: Path, started: float) -> list:
    artifacts = []
    total_bytes = 0
    for current, dirnames, filenames in os.walk(str(build_dir), followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in {"src", "pkg"}]
        for name in sorted(filenames):
            if not name.endswith(AUR_SANDBOX_ARTIFACT_SUFFIXES):
                continue
            path = Path(current) / name
            try:
                metadata = os.lstat(str(path))
            except OSError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if metadata.st_size <= 0:
                continue
            if metadata.st_mtime < started - 2:
                continue
            total_bytes += int(metadata.st_size)
            if total_bytes > AUR_SANDBOX_MAX_TOTAL_ARTIFACT_BYTES:
                raise SandboxBuildError("the isolated build produced oversized artifacts")
            if len(artifacts) >= AUR_SANDBOX_MAX_ARTIFACTS:
                raise SandboxBuildError("the isolated build produced too many artifacts")
            digest = _sha256_file(path)
            artifacts.append(
                SandboxArtifact(
                    name=name,
                    path=str(path),
                    size=int(metadata.st_size),
                    sha256=digest,
                )
            )
    return artifacts


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(str(path), "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
