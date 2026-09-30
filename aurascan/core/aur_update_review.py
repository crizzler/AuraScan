"""Guided review and installation of pending AUR updates.

The upgrade workflow's repository-only continuation deliberately drops planned
AUR builds from the automatic helper handoff. This module owns what happens
next: instead of printing instructions for the user to follow by hand, it can
download one AUR package with the trusted Git boundary, drive the
``aurascan-makepkg`` wrapper through a review-only step, and then - only after
the review passed and the user consented again - build and install the package
through the same wrapper and verify the installed version with the trusted
pacman boundary.

Safety boundaries owned here:

* the AUR URL is the canonical HTTPS prefix plus a strictly validated package
  name, so no other host or transport can be selected;
* the download is bounded, runs through the captured system Git with terminal
  prompts, credentials, hooks and LFS smudge disabled, and fails closed on any
  error, timeout or missing ``PKGBUILD``;
* the wrapper (a UI entry point supplied by the caller because core modules
  must not import it) owns every scan, blocking and manual-review decision; a
  blocked or review-required package is never built and this module never
  accepts a review on the user's behalf;
* the review step is followed, before any build consent, by a bounded static
  check of the PKGBUILD's literal ``depends``/``makedepends``/``checkdepends``
  declarations against the configured repositories: dependencies that pacman
  cannot install are reported with the exact reason, and a confirmed missing
  AUR dependency can be handed back to the same review-and-consent flow
  instead of running a build that would fail while installing dependencies;
* AI review is whatever the normal scan configuration provides, remains
  advisory, and can never lower a deterministic result;
* no passing scan is reported as proof that a package is safe, and every
  failure is reported with the reviewed copy's path so the user can continue
  deliberately.

The wrapper provider contract is ``wrapper_provider(makepkg_arguments, cwd,
stdout, stderr) -> str`` returning one of the ``WRAPPER_RESULT_*`` values.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, List, Optional, Sequence, TextIO, Tuple

from aurascan.core.pkgbuild_dependencies import (
    declared_build_dependencies,
    dependency_token_valid,
)
from aurascan.core.trusted_executable import (
    TRUSTED_PACMAN_PATH,
    TrustedExecutable,
    UnsafeUpgradeExecutable,
    capture_trusted_executable,
    revalidate_trusted_executable,
    run_trusted_command,
)
from aurascan.core.trusted_tools import (
    TrustedTool,
    TrustedToolError,
    capture_trusted_system_tool,
    revalidate_trusted_system_tool,
    run_bounded_trusted_tool,
)
from aurascan.core.upgrade_models import UpgradePackage

if TYPE_CHECKING:  # pragma: no cover - annotations only, never executed
    from aurascan.core.upgrade_preflight import UpgradeOptions


AUR_GIT_BASE_URL = "https://aur.archlinux.org/"
AUR_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9@._+-]{0,199}$")
AUR_CLONE_TIMEOUT_SECONDS = 120.0
AUR_REVISION_TIMEOUT_SECONDS = 30.0
AUR_SCAN_ONLY_ARGUMENT = "--aurascan-scan-only"
AUR_BUILD_MAKEPKG_ARGUMENTS = ("--syncdeps", "--install")
AUR_DEPENDENCY_CHECK_TIMEOUT_SECONDS = 15.0
AUR_DEPENDENCY_LOOKUP_TIMEOUT_SECONDS = 15.0
AUR_DEPENDENCY_CHAIN_LIMIT = 3
MAX_AUR_DEPENDENCY_LOOKUPS = 4
MAX_SHOWN_DEPENDENCIES = 8
MAX_CAPTURED_PKGBUILD_BYTES = 1024 * 1024

WRAPPER_RESULT_OK = "ok"
WRAPPER_RESULT_BLOCKED = "blocked"
WRAPPER_RESULT_REVIEW_REQUIRED = "review_required"
WRAPPER_RESULT_TOOL_UNAVAILABLE = "tool_unavailable"
WRAPPER_RESULT_FAILED = "failed"


class AurUpdateAcquisitionError(RuntimeError):
    """Bounded AUR download failure whose message is safe to print."""


@dataclass(frozen=True)
class AcquiredAurPackage:
    name: str
    path: Path
    revision: str


@dataclass(frozen=True)
class GuidedBuildDependencies:
    """Advisory classification of one PKGBUILD's declared build needs."""

    missing: Tuple[str, ...]
    repo_installable: Tuple[str, ...]
    unresolved: Tuple[str, ...]
    aur_only: Tuple[str, ...]


_TARGET_NOT_FOUND_RE = re.compile(r"^error: target not found: (.+)$", re.MULTILINE)


def pending_aur_update_lines(packages: Sequence[UpgradePackage], *, limit: int = 12) -> List[str]:
    lines: List[str] = []
    for package in packages[:limit]:
        if package.old_version and package.new_version:
            lines.append(f"- {package.name} {package.old_version} -> {package.new_version}")
        elif package.new_version:
            lines.append(f"- {package.name} -> {package.new_version}")
        else:
            lines.append(f"- {package.name}")
    if len(packages) > limit:
        lines.append(f"- ... and {len(packages) - limit} more")
    return lines


def print_pending_aur_update_guidance(packages: Sequence[UpgradePackage], *, stream: TextIO) -> None:
    """Print the AUR updates left for a separate, scanned build.

    The list is bounded package metadata already shown as inert evidence in the
    report, and the guidance points at the documented ``aurascan-makepkg``
    build path. It never claims a static scan makes the package safe.
    """
    if not packages:
        return
    print("[AuraScan] Pending AUR update(s) remain outside this transaction:", file=stream)
    for line in pending_aur_update_lines(packages):
        print(f"[AuraScan]   {line}", file=stream)
    print("[AuraScan] Scan and build each one through aurascan-makepkg before installing it, for example:", file=stream)
    print("[AuraScan]   cd <aur-package-directory> && aurascan-makepkg --syncdeps", file=stream)


def aur_update_review_available(packages: Sequence[UpgradePackage], options: "UpgradeOptions") -> bool:
    """Whether the guided AUR update flow may be offered to the user.

    Non-interactive runs (``--yes``, ``--json``, dry runs) keep the plain
    guidance instead, and the caller always decides whether a wrapper provider
    exists.
    """
    if not packages:
        return False
    if options.json_output or options.dry_run or options.yes:
        return False
    return True


def aur_package_git_url(name: str) -> str:
    """Return the canonical AUR Git URL for one validated package name."""

    candidate = str(name or "").strip()
    if not AUR_PACKAGE_NAME_RE.fullmatch(candidate):
        raise AurUpdateAcquisitionError("the planned update name is not a supported AUR package name")
    return AUR_GIT_BASE_URL + candidate + ".git"


def default_aur_update_work_root() -> Path:
    cache_home = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(cache_home) if cache_home else Path.home() / ".cache"
    return base / "aurascan" / "aur-updates"


def acquire_aur_package(
    name: str,
    *,
    work_root: Path,
    runner: Callable[..., object] = run_bounded_trusted_tool,
    which: Callable[[str], Optional[str]] = shutil.which,
    tool_capture: Callable[..., Optional[TrustedTool]] = capture_trusted_system_tool,
    tool_revalidate: Callable[[TrustedTool], None] = revalidate_trusted_system_tool,
) -> AcquiredAurPackage:
    """Download one AUR package with the captured system Git, bounded.

    The clone is shallow, credential-free, hook-free and prompt-free, and the
    exact HEAD revision plus a regular ``PKGBUILD`` are mandatory evidence.
    Any failure removes the partial checkout and raises a bounded error.
    """

    url = aur_package_git_url(name)
    try:
        git_tool = tool_capture("git", which=which)
    except (OSError, TypeError, TrustedToolError) as exc:
        raise AurUpdateAcquisitionError("the trusted system Git executable is unavailable") from exc
    if git_tool is None:
        raise AurUpdateAcquisitionError("the trusted system Git executable is unavailable")

    work_root = Path(work_root)
    try:
        work_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AurUpdateAcquisitionError("the AuraScan AUR download directory is unavailable") from exc
    checkout_dir = Path(tempfile.mkdtemp(prefix=name + ".", dir=str(work_root)))
    environment = {
        "HOME": str(work_root / "empty-home"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
        "SSH_AUTH_SOCK": "",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }

    def _fail(message: str) -> None:
        shutil.rmtree(str(checkout_dir), ignore_errors=True)
        raise AurUpdateAcquisitionError(message)

    try:
        Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _fail("the AuraScan AUR download directory is unavailable")

    try:
        tool_revalidate(git_tool)
        result = runner(
            [
                git_tool.path,
                "-c", "credential.helper=",
                "-c", "core.hooksPath=/dev/null",
                "clone",
                "--depth=1",
                "--single-branch",
                "--no-recurse-submodules",
                url,
                str(checkout_dir),
            ],
            capture_output=True,
            text=True,
            timeout=AUR_CLONE_TIMEOUT_SECONDS,
            env=environment,
            check=False,
        )
    except subprocess.SubprocessError:
        _fail("the AUR repository download failed or exceeded its time bound")
    except (OSError, TypeError, TrustedToolError):
        _fail("the AUR repository could not be downloaded")
    if int(getattr(result, "returncode", 1)) != 0:
        _fail("the AUR repository could not be downloaded")

    try:
        tool_revalidate(git_tool)
        revision_result = runner(
            [git_tool.path, "-C", str(checkout_dir), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            timeout=AUR_REVISION_TIMEOUT_SECONDS,
            env=environment,
            check=False,
        )
    except subprocess.SubprocessError:
        _fail("the AUR repository revision could not be established")
    except (OSError, TypeError, TrustedToolError):
        _fail("the AUR repository revision could not be established")
    if int(getattr(revision_result, "returncode", 1)) != 0:
        _fail("the AUR repository revision could not be established")
    revision = str(getattr(revision_result, "stdout", "") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        _fail("the AUR repository revision could not be established")

    pkgbuild_path = checkout_dir / "PKGBUILD"
    try:
        pkgbuild_stat = os.lstat(str(pkgbuild_path))
    except OSError:
        _fail("the AUR repository did not contain a PKGBUILD")
    if not stat.S_ISREG(pkgbuild_stat.st_mode):
        _fail("the AUR repository PKGBUILD was not a regular file")

    return AcquiredAurPackage(name=name, path=checkout_dir, revision=revision)


def query_installed_package_version(
    name: str,
    *,
    runner: Callable[..., object] = subprocess.run,
    executable_capture: Callable[..., Optional[TrustedExecutable]] = capture_trusted_executable,
    executable_revalidate: Callable[[TrustedExecutable], None] = revalidate_trusted_executable,
) -> str:
    """Read the installed version through the trusted pacman boundary.

    Failure is reported as an empty string; verification never blocks the
    guided flow, it only decides which summary is printed.
    """

    try:
        pacman = executable_capture("pacman", TRUSTED_PACMAN_PATH)
    except (OSError, TypeError, UnsafeUpgradeExecutable):
        return ""
    if pacman is None:
        return ""
    try:
        executable_revalidate(pacman)
        result = run_trusted_command(
            [pacman.path, "-Q", name],
            [pacman],
            runner=runner,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, TypeError, UnsafeUpgradeExecutable):
        return ""
    output = str(getattr(result, "stdout", "") or "")
    for raw in output.splitlines():
        parts = raw.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0] == name:
            return parts[1]
    return ""


def _package_label(package: UpgradePackage) -> str:
    name = str(getattr(package, "name", "") or "")
    new_version = str(getattr(package, "new_version", "") or "")
    return name + (f" {new_version}" if new_version else "")


def read_captured_pkgbuild(pkgbuild_path: Path) -> Optional[str]:
    """Read one captured PKGBUILD as bounded text, or return ``None``."""

    try:
        info = os.lstat(str(pkgbuild_path))
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CAPTURED_PKGBUILD_BYTES:
        return None
    try:
        with open(str(pkgbuild_path), "rb") as handle:
            raw = handle.read(MAX_CAPTURED_PKGBUILD_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_CAPTURED_PKGBUILD_BYTES:
        return None
    return raw.decode("utf-8", "replace")


def _run_trusted_pacman(
    arguments: Sequence[str],
    *,
    runner: Callable[..., object],
    executable_capture: Callable[..., Optional[TrustedExecutable]],
    executable_revalidate: Callable[[TrustedExecutable], None],
) -> Optional[Tuple[int, str, str]]:
    """Run one read-only pacman query through the trusted boundary."""

    try:
        pacman = executable_capture("pacman", TRUSTED_PACMAN_PATH)
    except (OSError, TypeError, UnsafeUpgradeExecutable):
        return None
    if pacman is None:
        return None
    try:
        executable_revalidate(pacman)
        result = run_trusted_command(
            [pacman.path, *arguments],
            [pacman],
            runner=runner,
            capture_output=True,
            text=True,
            timeout=AUR_DEPENDENCY_CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, TypeError, UnsafeUpgradeExecutable, subprocess.SubprocessError):
        return None
    return (
        int(getattr(result, "returncode", 1)),
        str(getattr(result, "stdout", "") or ""),
        str(getattr(result, "stderr", "") or ""),
    )


def _target_not_found(stderr: str, dependency: str) -> bool:
    return any(
        match.group(1).strip() == dependency
        for match in _TARGET_NOT_FOUND_RE.finditer(stderr)
    )


def _aur_dependency_exists(
    name: str,
    *,
    work_root: Path,
    runner: Callable[..., object],
    which: Callable[[str], Optional[str]],
    tool_capture: Callable[..., Optional[TrustedTool]],
    tool_revalidate: Callable[[TrustedTool], None],
) -> bool:
    """Positively confirm one dependency name as an available AUR package."""

    if not AUR_PACKAGE_NAME_RE.fullmatch(name):
        return False
    try:
        git_tool = tool_capture("git", which=which)
    except (OSError, TypeError, TrustedToolError):
        return False
    if git_tool is None:
        return False
    environment = {
        "HOME": str(work_root / "empty-home"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
        "SSH_AUTH_SOCK": "",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    try:
        Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    try:
        tool_revalidate(git_tool)
        result = runner(
            [
                git_tool.path,
                "-c", "credential.helper=",
                "-c", "core.hooksPath=/dev/null",
                "ls-remote",
                "--exit-code",
                AUR_GIT_BASE_URL + name + ".git",
            ],
            capture_output=True,
            text=True,
            timeout=AUR_DEPENDENCY_LOOKUP_TIMEOUT_SECONDS,
            env=environment,
            check=False,
        )
    except (OSError, TypeError, TrustedToolError, subprocess.SubprocessError):
        return False
    return int(getattr(result, "returncode", 1)) == 0


def check_guided_build_dependencies(
    pkgbuild_content: str,
    *,
    work_root: Path,
    pacman_runner: Callable[..., object],
    pacman_capture: Callable[..., Optional[TrustedExecutable]],
    pacman_revalidate: Callable[[TrustedExecutable], None],
    runner: Callable[..., object],
    which: Callable[[str], Optional[str]],
    tool_capture: Callable[..., Optional[TrustedTool]],
    tool_revalidate: Callable[[TrustedTool], None],
) -> Optional[GuidedBuildDependencies]:
    """Classify declared build dependencies; ``None`` means unknown.

    This is an advisory pre-build explanation, never a policy decision.  It
    uses only read-only pacman queries (``-T`` and ``-Sp``) and, for a
    confirmed miss, one bounded ``git ls-remote`` lookup.  Any unexpected
    result, parser doubt, or tool failure returns ``None`` so the caller
    keeps the existing behavior without making claims.
    """

    declared = declared_build_dependencies(pkgbuild_content)
    if declared is None:
        return None
    if not declared:
        return GuidedBuildDependencies((), (), (), ())
    deptest = _run_trusted_pacman(
        ["-T", *declared],
        runner=pacman_runner,
        executable_capture=pacman_capture,
        executable_revalidate=pacman_revalidate,
    )
    if deptest is None:
        return None
    returncode, out, _err = deptest
    missing = tuple(
        line.strip()
        for line in out.splitlines()
        if dependency_token_valid(line.strip())
    )
    if not missing:
        return GuidedBuildDependencies((), (), (), ()) if returncode == 0 else None
    repo_installable: List[str] = []
    unresolved: List[str] = []
    for dependency in missing:
        resolution = _run_trusted_pacman(
            ["-S", "-p", "--noconfirm", "--print-format", "%n", dependency],
            runner=pacman_runner,
            executable_capture=pacman_capture,
            executable_revalidate=pacman_revalidate,
        )
        if resolution is None:
            return None
        rc, _resolution_out, resolution_err = resolution
        if rc == 0:
            # ``pacman -Sp`` prints the whole transaction, so the provider a
            # virtual dependency resolves to is not reported here; only
            # resolvability is claimed.
            repo_installable.append(dependency)
            continue
        if _target_not_found(resolution_err, dependency):
            unresolved.append(dependency)
            continue
        return None
    aur_only: List[str] = []
    for dependency in unresolved[:MAX_AUR_DEPENDENCY_LOOKUPS]:
        if AUR_PACKAGE_NAME_RE.fullmatch(dependency) and _aur_dependency_exists(
            dependency,
            work_root=work_root,
            runner=runner,
            which=which,
            tool_capture=tool_capture,
            tool_revalidate=tool_revalidate,
        ):
            aur_only.append(dependency)
    return GuidedBuildDependencies(
        missing=missing,
        repo_installable=tuple(repo_installable),
        unresolved=tuple(unresolved),
        aur_only=tuple(aur_only),
    )


def _print_dependency_summary(
    name: str,
    check: GuidedBuildDependencies,
    *,
    stdout: TextIO,
) -> None:
    if check.repo_installable:
        shown = ", ".join(check.repo_installable[:MAX_SHOWN_DEPENDENCIES])
        suffix = "" if len(check.repo_installable) <= MAX_SHOWN_DEPENDENCIES else ", ..."
        print(
            "[AuraScan] The build step will install missing build dependencies with sudo: "
            + shown
            + suffix
            + ".",
            file=stdout,
        )
    for dependency in check.unresolved[:MAX_SHOWN_DEPENDENCIES]:
        if dependency in check.aur_only:
            print(
                f"[AuraScan] Build dependency {dependency} is not in your configured repositories; "
                f"it is available in the AUR (https://aur.archlinux.org/packages/{dependency}).",
                file=stdout,
            )
        else:
            print(
                f"[AuraScan] Build dependency {dependency} is not available in your configured repositories.",
                file=stdout,
            )


def _print_dependency_stop(
    name: str,
    acquired: AcquiredAurPackage,
    *,
    chain_limited: bool,
    stderr: TextIO,
) -> None:
    print(
        f"[AuraScan] {name} was not built: makepkg installs missing build dependencies through pacman, "
        "and the declared dependencies above cannot be installed that way. Nothing was installed.",
        file=stderr,
    )
    if chain_limited:
        print(
            "[AuraScan] A guided build of the missing AUR dependency was not offered because the dependency chain limit was reached.",
            file=stderr,
        )
    print(
        f"[AuraScan] The reviewed copy is at {acquired.path}; after the dependencies are available, "
        "run: aurascan-makepkg --syncdeps --install",
        file=stderr,
    )


def _resolve_build_dependencies(
    name: str,
    acquired: AcquiredAurPackage,
    *,
    chain: Tuple[str, ...],
    input_func: Callable[[str], str],
    stdout: TextIO,
    stderr: TextIO,
    wrapper_provider: Callable[..., str],
    work_root: Path,
    runner: Callable[..., object],
    which: Callable[[str], Optional[str]],
    tool_capture: Callable[..., Optional[TrustedTool]],
    tool_revalidate: Callable[[TrustedTool], None],
    pacman_runner: Callable[..., object],
    pacman_capture: Callable[..., Optional[TrustedExecutable]],
    pacman_revalidate: Callable[[TrustedExecutable], None],
) -> bool:
    """Explain and, when possible, resolve missing build dependencies.

    Returns True when the flow may continue to the build-consent prompt and
    False when it must stop.  Every resolution step is read-only or a fully
    reviewed, separately consented guided build of the dependency itself.
    """

    attempted: set = set()
    chain_limited = False
    last_report = None
    while True:
        content = read_captured_pkgbuild(acquired.path / "PKGBUILD")
        if content is None:
            return True
        check = check_guided_build_dependencies(
            content,
            work_root=work_root,
            pacman_runner=pacman_runner,
            pacman_capture=pacman_capture,
            pacman_revalidate=pacman_revalidate,
            runner=runner,
            which=which,
            tool_capture=tool_capture,
            tool_revalidate=tool_revalidate,
        )
        if check is None:
            return True
        report = (check.missing, check.repo_installable, check.unresolved, check.aur_only)
        if report != last_report:
            _print_dependency_summary(name, check, stdout=stdout)
            last_report = report
        if not check.unresolved:
            return True
        offerable = []
        for dependency in check.aur_only:
            if dependency in attempted:
                continue
            if dependency in chain or len(chain) >= AUR_DEPENDENCY_CHAIN_LIMIT:
                chain_limited = True
                continue
            offerable.append(dependency)
        if not offerable:
            _print_dependency_stop(
                name,
                acquired,
                chain_limited=chain_limited,
                stderr=stderr,
            )
            return False
        for dependency in offerable:
            attempted.add(dependency)
            answer = _read_answer(
                input_func,
                f"{dependency} is an AUR package and is not installed. "
                "Download, review, build and install it through AuraScan first? [Y/n] ",
            )
            if answer is not None and answer in {"", "y", "yes"}:
                _handle_single_aur_update(
                    UpgradePackage(name=dependency, repo="aur"),
                    input_func=input_func,
                    stdout=stdout,
                    stderr=stderr,
                    wrapper_provider=wrapper_provider,
                    work_root=work_root,
                    runner=runner,
                    which=which,
                    tool_capture=tool_capture,
                    tool_revalidate=tool_revalidate,
                    pacman_runner=pacman_runner,
                    pacman_capture=pacman_capture,
                    pacman_revalidate=pacman_revalidate,
                    chain=chain + (name,),
                    dependency_of=name,
                )
                break
            print(f"[AuraScan] Skipped the guided build of {dependency}.", file=stdout)
        # Re-check the parent package's dependencies after one attempt.


def _read_answer(input_func: Callable[[str], str], prompt: str) -> Optional[str]:
    """Return the normalized answer, or None when no interactive answer came."""

    try:
        return input_func(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return None


def offer_aur_update_review(
    packages: Sequence[UpgradePackage],
    options: "UpgradeOptions",
    *,
    input_func: Callable[[str], str],
    stdout: TextIO,
    stderr: TextIO,
    wrapper_provider: Optional[Callable[..., str]] = None,
    work_root: Optional[Path] = None,
    runner: Callable[..., object] = run_bounded_trusted_tool,
    which: Callable[[str], Optional[str]] = shutil.which,
    tool_capture: Callable[..., Optional[TrustedTool]] = capture_trusted_system_tool,
    tool_revalidate: Callable[[TrustedTool], None] = revalidate_trusted_system_tool,
    pacman_runner: Callable[..., object] = subprocess.run,
    pacman_capture: Callable[..., Optional[TrustedExecutable]] = capture_trusted_executable,
    pacman_revalidate: Callable[[TrustedExecutable], None] = revalidate_trusted_executable,
) -> bool:
    """Offer the guided download, review, build and install flow per package.

    Returns True when the flow was offered (the function prints every outcome
    and its own guidance), and False when the caller should print the plain
    pending-update guidance instead.
    """

    if wrapper_provider is None or not aur_update_review_available(packages, options):
        return False

    resolved_work_root = Path(work_root) if work_root is not None else default_aur_update_work_root()
    count = len(packages)
    label = "update" if count == 1 else "updates"
    print("", file=stdout)
    print("[AuraScan] AUR update handling", file=stdout)
    print(
        f"[AuraScan] {count} pending AUR {label} can be downloaded, reviewed, and - only when the review passes - built and installed through AuraScan.",
        file=stdout,
    )

    for index, package in enumerate(packages):
        print("", file=stdout)
        print(f"[AuraScan] Pending AUR update: {_package_label(package)}", file=stdout)
        answer = _read_answer(
            input_func,
            "Download and review it from the Arch User Repository now? "
            "AuraScan will build and install it only if the review passes. [Y/n] ",
        )
        if answer is None:
            print(
                "[AuraScan] No interactive answer; skipping the remaining AUR update(s).",
                file=stderr,
            )
            print_pending_aur_update_guidance(list(packages[index:]), stream=stderr)
            return True
        if answer not in {"", "y", "yes"}:
            print(f"[AuraScan] Skipped {package.name}.", file=stdout)
            print_pending_aur_update_guidance([package], stream=stdout)
            continue
        _handle_single_aur_update(
            package,
            input_func=input_func,
            stdout=stdout,
            stderr=stderr,
            wrapper_provider=wrapper_provider,
            work_root=resolved_work_root,
            runner=runner,
            which=which,
            tool_capture=tool_capture,
            tool_revalidate=tool_revalidate,
            pacman_runner=pacman_runner,
            pacman_capture=pacman_capture,
            pacman_revalidate=pacman_revalidate,
        )
    return True


def _handle_single_aur_update(
    package: UpgradePackage,
    *,
    input_func: Callable[[str], str],
    stdout: TextIO,
    stderr: TextIO,
    wrapper_provider: Callable[..., str],
    work_root: Path,
    runner: Callable[..., object],
    which: Callable[[str], Optional[str]],
    tool_capture: Callable[..., Optional[TrustedTool]],
    tool_revalidate: Callable[[TrustedTool], None],
    pacman_runner: Callable[..., object],
    pacman_capture: Callable[..., Optional[TrustedExecutable]],
    pacman_revalidate: Callable[[TrustedExecutable], None],
    chain: Tuple[str, ...] = (),
    dependency_of: str = "",
) -> None:
    name = str(getattr(package, "name", "") or "")
    context = f" (build dependency of {dependency_of})" if dependency_of else ""
    print(
        f"[AuraScan] Downloading {name}{context} from the Arch User Repository...",
        file=stdout,
    )
    try:
        acquired = acquire_aur_package(
            name,
            work_root=work_root,
            runner=runner,
            which=which,
            tool_capture=tool_capture,
            tool_revalidate=tool_revalidate,
        )
    except AurUpdateAcquisitionError as exc:
        print(f"[AuraScan] Could not download {name}: {exc}.", file=stderr)
        print_pending_aur_update_guidance([package], stream=stderr)
        return
    print(
        f"[AuraScan] Reviewing {name} (AUR revision {acquired.revision[:12]})...",
        file=stdout,
    )
    review_result = wrapper_provider(
        [AUR_SCAN_ONLY_ARGUMENT],
        acquired.path,
        stdout,
        stderr,
    )
    if review_result == WRAPPER_RESULT_BLOCKED:
        print(
            f"[AuraScan] {name} was not built: AuraScan's review blocked it. "
            "Follow the findings above before building it yourself.",
            file=stderr,
        )
        return
    if review_result == WRAPPER_RESULT_REVIEW_REQUIRED:
        print(
            f"[AuraScan] {name} needs a manual review decision before it can be built. "
            "The review token and the exact next command were printed above.",
            file=stderr,
        )
        return
    if review_result == WRAPPER_RESULT_TOOL_UNAVAILABLE:
        print(
            f"[AuraScan] The trusted system makepkg executable is unavailable, so {name} was not built. "
            f"Install base-devel, then run in {acquired.path}: aurascan-makepkg --syncdeps --install",
            file=stderr,
        )
        return
    if review_result != WRAPPER_RESULT_OK:
        print(
            f"[AuraScan] The review step for {name} did not complete. "
            f"The downloaded copy is at {acquired.path}; rerun aurascan-makepkg there to retry.",
            file=stderr,
        )
        return

    if not _resolve_build_dependencies(
        name,
        acquired,
        chain=chain,
        input_func=input_func,
        stdout=stdout,
        stderr=stderr,
        wrapper_provider=wrapper_provider,
        work_root=work_root,
        runner=runner,
        which=which,
        tool_capture=tool_capture,
        tool_revalidate=tool_revalidate,
        pacman_runner=pacman_runner,
        pacman_capture=pacman_capture,
        pacman_revalidate=pacman_revalidate,
    ):
        return

    answer = _read_answer(
        input_func,
        f"AuraScan's review passed for {name}{context}. Build and install it now with aurascan-makepkg? "
        "This can ask for your password. [Y/n] ",
    )
    if answer is None or answer not in {"", "y", "yes"}:
        print(
            f"[AuraScan] Build skipped for {name}. The reviewed copy is at {acquired.path}; "
            "run aurascan-makepkg --syncdeps --install there when you want to build it.",
            file=stdout,
        )
        return
    build_result = wrapper_provider(
        list(AUR_BUILD_MAKEPKG_ARGUMENTS),
        acquired.path,
        stdout,
        stderr,
    )
    if build_result == WRAPPER_RESULT_BLOCKED:
        print(
            f"[AuraScan] {name} was not built: AuraScan's review blocked it. "
            "Follow the findings above before building it yourself.",
            file=stderr,
        )
        return
    if build_result == WRAPPER_RESULT_REVIEW_REQUIRED:
        print(
            f"[AuraScan] {name} needs a manual review decision before it can be built. "
            "The review token and the exact next command were printed above.",
            file=stderr,
        )
        return
    if build_result == WRAPPER_RESULT_TOOL_UNAVAILABLE:
        print(
            f"[AuraScan] The trusted system makepkg executable is unavailable, so {name} was not built. "
            f"Install base-devel, then run in {acquired.path}: aurascan-makepkg --syncdeps --install",
            file=stderr,
        )
        return
    if build_result != WRAPPER_RESULT_OK:
        print(
            f"[AuraScan] The build and install step for {name} did not complete. "
            f"Retry in {acquired.path} with: aurascan-makepkg --syncdeps --install",
            file=stderr,
        )
        return

    installed = query_installed_package_version(
        name,
        runner=pacman_runner,
        executable_capture=pacman_capture,
        executable_revalidate=pacman_revalidate,
    )
    expected = str(getattr(package, "new_version", "") or "").strip()
    if installed and expected and installed == expected:
        print(f"[AuraScan] Verified: {name} {installed} is installed.", file=stdout)
    elif installed:
        detail = (
            f" The pending update was reported as {expected}; the Arch User Repository may have changed since the preflight."
            if expected and expected != installed
            else ""
        )
        print(f"[AuraScan] Installed {name} {installed}.{detail}", file=stdout)
    else:
        print(
            f"[AuraScan] The build and install step for {name} completed, but AuraScan could not verify the installed version with pacman.",
            file=stderr,
        )
