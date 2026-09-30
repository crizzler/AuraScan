"""Tests for the guided AUR update review, build, and install flow."""

import io
from pathlib import Path

import pytest

from aurascan import makepkg_wrapper
from aurascan.core import trusted_executable
from aurascan.core.aur_update_review import (
    AUR_BUILD_MAKEPKG_ARGUMENTS,
    AUR_CLONE_TIMEOUT_SECONDS,
    AUR_SCAN_ONLY_ARGUMENT,
    WRAPPER_RESULT_BLOCKED,
    WRAPPER_RESULT_FAILED,
    WRAPPER_RESULT_OK,
    WRAPPER_RESULT_REVIEW_REQUIRED,
    WRAPPER_RESULT_TOOL_UNAVAILABLE,
    AurUpdateAcquisitionError,
    acquire_aur_package,
    aur_package_git_url,
    aur_update_review_available,
    check_guided_build_dependencies,
    offer_aur_update_review,
    query_installed_package_version,
    read_captured_pkgbuild,
)
from aurascan.core.trusted_executable import TrustedExecutable
from aurascan.core.trusted_tools import TrustedTool, TrustedToolError
from aurascan.core.upgrade_models import UpgradePackage
from aurascan.core.upgrade_preflight import UpgradeOptions


@pytest.fixture(autouse=True)
def allow_fixture_executable_revalidation(monkeypatch):
    # The shared command helper revalidates through its own module globals.
    monkeypatch.setattr(
        trusted_executable,
        "revalidate_trusted_executable",
        lambda _executable: None,
    )


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeInput:
    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


class FakeWrapperProvider:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, arguments, cwd, stdout, stderr):
        self.calls.append((list(arguments), Path(cwd)))
        if not self.results:
            raise AssertionError("unexpected wrapper step")
        return self.results.pop(0)


class RevalidateRecorder:
    def __init__(self):
        self.calls = 0

    def __call__(self, _tool):
        self.calls += 1


def fake_git_capture(name, *, which=None):
    if name != "git":
        raise AssertionError("unexpected tool capture")
    return TrustedTool("git", "/usr/bin/git", 1, 2, 0, 0, 0o100755)


def fake_pacman_capture(name, path):
    if name != "pacman":
        raise AssertionError("unexpected executable capture")
    return TrustedExecutable("pacman", path, 1, 3, 0, 0, 0o100755)


def git_runner(
    record,
    *,
    revision="a" * 40,
    clone_returncode=0,
    revision_returncode=0,
    create_pkgbuild=True,
    pkgbuild_kind="file",
):
    def runner(argv, **kwargs):
        argv = list(argv)
        record.append((argv, kwargs))
        if "clone" in argv:
            target = Path(argv[-1])
            if create_pkgbuild:
                target.mkdir(parents=True, exist_ok=True)
                pkgbuild = target / "PKGBUILD"
                if pkgbuild_kind == "file":
                    pkgbuild.write_text("pkgname=demo-bin\npkgver=2\n", encoding="utf-8")
                elif pkgbuild_kind == "directory":
                    pkgbuild.mkdir()
                elif pkgbuild_kind == "symlink":
                    (target / "real-pkgbuild").write_text("x", encoding="utf-8")
                    pkgbuild.symlink_to(target / "real-pkgbuild")
            return FakeCompleted(clone_returncode)
        if "rev-parse" in argv:
            return FakeCompleted(revision_returncode, revision + "\n")
        return FakeCompleted(1)

    return runner


def pacman_query_runner(stdout_text):
    calls = []

    def runner(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return FakeCompleted(0, stdout_text)

    return runner, calls


def options(**overrides):
    resolved = UpgradeOptions()
    for key, value in overrides.items():
        setattr(resolved, key, value)
    return resolved


def package(name="demo-bin", old_version="1", new_version="2"):
    return UpgradePackage(
        name=name,
        old_version=old_version,
        new_version=new_version,
        repo="aur",
        package_type="aur",
    )


def run_offer(tmp_path, packages, answers, wrapper_results, **overrides):
    work_root = overrides.pop("work_root", tmp_path / "aur-updates")
    record = []
    revalidate = RevalidateRecorder()
    provider = FakeWrapperProvider(wrapper_results)
    input_func = FakeInput(answers)
    stdout = io.StringIO()
    stderr = io.StringIO()
    handled = offer_aur_update_review(
        packages,
        overrides.pop("options", options()),
        input_func=input_func,
        stdout=stdout,
        stderr=stderr,
        wrapper_provider=overrides.pop("wrapper_provider", provider),
        work_root=work_root,
        runner=overrides.pop("runner", git_runner(record)),
        which=lambda name: "/usr/bin/" + name,
        tool_capture=overrides.pop("tool_capture", fake_git_capture),
        tool_revalidate=overrides.pop("tool_revalidate", revalidate),
        pacman_runner=overrides.pop(
            "pacman_runner",
            pacman_query_runner("demo-bin 2\n")[0],
        ),
        pacman_capture=overrides.pop("pacman_capture", fake_pacman_capture),
        pacman_revalidate=overrides.pop("pacman_revalidate", lambda _executable: None),
    )
    return {
        "handled": handled,
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
        "provider": provider,
        "input": input_func,
        "record": record,
        "work_root": work_root,
    }


# -- acquisition ----------------------------------------------------------


def test_aur_package_git_url_accepts_supported_names():
    assert aur_package_git_url("lib32-openal") == "https://aur.archlinux.org/lib32-openal.git"
    assert aur_package_git_url("python-foo_bar+baz@qux.a") == (
        "https://aur.archlinux.org/python-foo_bar+baz@qux.a.git"
    )


@pytest.mark.parametrize(
    "name",
    ["../evil", "-option", "Uppercase", "has space", "", "a" * 201, "na/me"],
)
def test_aur_package_git_url_rejects_unsupported_names(name):
    with pytest.raises(AurUpdateAcquisitionError, match="not a supported AUR package name"):
        aur_package_git_url(name)


def test_acquire_aur_package_clones_through_trusted_git(tmp_path):
    record = []
    revalidate = RevalidateRecorder()
    work_root = tmp_path / "root"

    acquired = acquire_aur_package(
        "demo-bin",
        work_root=work_root,
        runner=git_runner(record),
        which=lambda name: "/usr/bin/" + name,
        tool_capture=fake_git_capture,
        tool_revalidate=revalidate,
    )

    assert acquired.name == "demo-bin"
    assert acquired.revision == "a" * 40
    assert acquired.path.is_dir()
    assert acquired.path.parent == work_root
    assert (acquired.path / "PKGBUILD").is_file()
    assert revalidate.calls == 2

    clone_argv, clone_kwargs = record[0]
    assert clone_argv[:4] == ["/usr/bin/git", "-c", "credential.helper=", "-c"]
    assert clone_argv[4] == "core.hooksPath=/dev/null"
    assert clone_argv[5] == "clone"
    assert "--depth=1" in clone_argv
    assert clone_argv[-2] == "https://aur.archlinux.org/demo-bin.git"
    assert clone_argv[-1] == str(acquired.path)
    assert clone_kwargs["timeout"] == AUR_CLONE_TIMEOUT_SECONDS
    assert clone_kwargs["capture_output"] is True
    assert clone_kwargs["check"] is False
    environment = clone_kwargs["env"]
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_ASKPASS"] == "true"
    assert environment["SSH_AUTH_SOCK"] == ""
    assert environment["HOME"].endswith("empty-home")

    revision_argv = record[1][0]
    assert revision_argv[:2] == ["/usr/bin/git", "-C"]
    assert revision_argv[-2:] == ["--verify", "HEAD"]


def test_acquire_aur_package_fails_closed_on_clone_failure(tmp_path):
    record = []
    work_root = tmp_path / "root"

    with pytest.raises(AurUpdateAcquisitionError, match="could not be downloaded"):
        acquire_aur_package(
            "demo-bin",
            work_root=work_root,
            runner=git_runner(record, clone_returncode=1),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=fake_git_capture,
            tool_revalidate=RevalidateRecorder(),
        )

    assert sorted(path.name for path in work_root.iterdir()) == ["empty-home"]


def test_acquire_aur_package_fails_closed_without_trusted_git(tmp_path):
    with pytest.raises(AurUpdateAcquisitionError, match="trusted system Git executable is unavailable"):
        acquire_aur_package(
            "demo-bin",
            work_root=tmp_path / "root",
            runner=git_runner([]),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=lambda name, which=None: None,
            tool_revalidate=RevalidateRecorder(),
        )

    def hostile_capture(name, *, which=None):
        raise TrustedToolError("fixture untrusted path")

    with pytest.raises(AurUpdateAcquisitionError, match="trusted system Git executable is unavailable"):
        acquire_aur_package(
            "demo-bin",
            work_root=tmp_path / "root",
            runner=git_runner([]),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=hostile_capture,
            tool_revalidate=RevalidateRecorder(),
        )


def test_acquire_aur_package_requires_resolvable_revision(tmp_path):
    with pytest.raises(AurUpdateAcquisitionError, match="revision could not be established"):
        acquire_aur_package(
            "demo-bin",
            work_root=tmp_path / "root",
            runner=git_runner([], revision="not-a-revision"),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=fake_git_capture,
            tool_revalidate=RevalidateRecorder(),
        )

    with pytest.raises(AurUpdateAcquisitionError, match="revision could not be established"):
        acquire_aur_package(
            "demo-bin",
            work_root=tmp_path / "root",
            runner=git_runner([], revision_returncode=1),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=fake_git_capture,
            tool_revalidate=RevalidateRecorder(),
        )


def test_acquire_aur_package_requires_regular_pkgbuild(tmp_path):
    with pytest.raises(AurUpdateAcquisitionError, match="did not contain a PKGBUILD"):
        acquire_aur_package(
            "demo-bin",
            work_root=tmp_path / "root",
            runner=git_runner([], create_pkgbuild=False),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=fake_git_capture,
            tool_revalidate=RevalidateRecorder(),
        )

    with pytest.raises(AurUpdateAcquisitionError, match="was not a regular file"):
        acquire_aur_package(
            "demo-bin",
            work_root=tmp_path / "root",
            runner=git_runner([], pkgbuild_kind="directory"),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=fake_git_capture,
            tool_revalidate=RevalidateRecorder(),
        )

    with pytest.raises(AurUpdateAcquisitionError, match="was not a regular file"):
        acquire_aur_package(
            "demo-bin",
            work_root=tmp_path / "root",
            runner=git_runner([], pkgbuild_kind="symlink"),
            which=lambda name: "/usr/bin/" + name,
            tool_capture=fake_git_capture,
            tool_revalidate=RevalidateRecorder(),
        )


def test_query_installed_package_version_parses_and_fails_soft(tmp_path):
    runner, calls = pacman_query_runner("demo-bin 2\n")

    version = query_installed_package_version(
        "demo-bin",
        runner=runner,
        executable_capture=fake_pacman_capture,
        executable_revalidate=lambda _executable: None,
    )

    assert version == "2"
    assert calls[0][0] == ["/usr/bin/pacman", "-Q", "demo-bin"]

    unknown = query_installed_package_version(
        "other",
        runner=pacman_query_runner("demo-bin 2\n")[0],
        executable_capture=fake_pacman_capture,
        executable_revalidate=lambda _executable: None,
    )
    assert unknown == ""

    def broken_capture(_name, _path):
        raise trusted_executable.UnsafeUpgradeExecutable("fixture")

    assert query_installed_package_version(
        "demo-bin",
        runner=runner,
        executable_capture=broken_capture,
        executable_revalidate=lambda _executable: None,
    ) == ""


# -- guided flow ----------------------------------------------------------


def test_offer_full_flow_builds_and_verifies(tmp_path):
    result = run_offer(
        tmp_path,
        [package()],
        ["y", "y"],
        [WRAPPER_RESULT_OK, WRAPPER_RESULT_OK],
    )

    assert result["handled"] is True
    assert [arguments for arguments, _cwd in result["provider"].calls] == [
        [AUR_SCAN_ONLY_ARGUMENT],
        list(AUR_BUILD_MAKEPKG_ARGUMENTS),
    ]
    reviewed_dir = result["provider"].calls[0][1]
    assert reviewed_dir.is_dir()
    assert result["provider"].calls[1][1] == reviewed_dir
    assert reviewed_dir.parent == result["work_root"]
    output = result["stdout"]
    assert "AuraScan review passed" not in output  # the wrapper prints that, not this module
    assert "Build and install it now" in result["input"].prompts[1]
    assert "Verified: demo-bin 2 is installed." in output


def test_offer_declined_download_prints_guidance(tmp_path):
    result = run_offer(
        tmp_path,
        [package()],
        ["n"],
        [],
    )

    assert result["handled"] is True
    assert result["provider"].calls == []
    assert result["record"] == []
    assert "Skipped demo-bin." in result["stdout"]
    assert "aurascan-makepkg --syncdeps" in result["stdout"]


def test_offer_blocked_review_stops_before_build_prompt(tmp_path):
    result = run_offer(
        tmp_path,
        [package()],
        ["y"],
        [WRAPPER_RESULT_BLOCKED],
    )

    assert result["handled"] is True
    assert [arguments for arguments, _cwd in result["provider"].calls] == [[AUR_SCAN_ONLY_ARGUMENT]]
    assert len(result["input"].prompts) == 1
    assert "was not built" in result["stderr"]


def test_offer_review_required_stops_before_build_prompt(tmp_path):
    result = run_offer(
        tmp_path,
        [package()],
        ["y"],
        [WRAPPER_RESULT_REVIEW_REQUIRED],
    )

    assert result["handled"] is True
    assert len(result["provider"].calls) == 1
    assert len(result["input"].prompts) == 1
    assert "needs a manual review decision" in result["stderr"]


def test_offer_build_failure_prints_retry_path(tmp_path):
    result = run_offer(
        tmp_path,
        [package()],
        ["y", "y"],
        [WRAPPER_RESULT_OK, WRAPPER_RESULT_FAILED],
    )

    assert result["handled"] is True
    assert len(result["provider"].calls) == 2
    assert "did not complete" in result["stderr"]
    assert str(result["provider"].calls[1][1]) in result["stderr"]


def test_offer_tool_unavailable_reports_install_hint(tmp_path):
    result = run_offer(
        tmp_path,
        [package()],
        ["y"],
        [WRAPPER_RESULT_TOOL_UNAVAILABLE],
    )

    assert result["handled"] is True
    assert len(result["provider"].calls) == 1
    assert "trusted system makepkg executable is unavailable" in result["stderr"]


def test_offer_acquisition_failure_prints_manual_guidance(tmp_path):
    result = run_offer(
        tmp_path,
        [package()],
        ["y"],
        [],
        runner=git_runner([], clone_returncode=1),
    )

    assert result["handled"] is True
    assert result["provider"].calls == []
    assert "Could not download demo-bin" in result["stderr"]
    assert "aurascan-makepkg --syncdeps" in result["stderr"]


def test_offer_eof_skips_remaining_packages(tmp_path):
    result = run_offer(
        tmp_path,
        [package(), package(name="other-aur")],
        [],
        [],
    )

    assert result["handled"] is True
    assert result["provider"].calls == []
    assert "No interactive answer" in result["stderr"]
    assert "demo-bin 1 -> 2" in result["stderr"]
    assert "other-aur 1 -> 2" in result["stderr"]


def test_offer_continues_after_user_skips_one_package(tmp_path):
    result = run_offer(
        tmp_path,
        [package(name="first-aur"), package(name="second-aur")],
        ["n", "y", "n"],
        [WRAPPER_RESULT_OK],
    )

    assert result["handled"] is True
    assert [arguments for arguments, _cwd in result["provider"].calls] == [[AUR_SCAN_ONLY_ARGUMENT]]
    reviewed_dir = result["provider"].calls[0][1]
    assert "second-aur" in reviewed_dir.name
    assert "Skipped first-aur." in result["stdout"]
    assert "Build skipped for second-aur." in result["stdout"]


@pytest.mark.parametrize(
    "override",
    [
        {"yes": True},
        {"json_output": True},
        {"dry_run": True},
    ],
)
def test_offer_not_available_for_noninteractive_modes(tmp_path, override):
    assert aur_update_review_available([package()], options(**override)) is False
    result = run_offer(tmp_path, [package()], ["y", "y"], [], options=options(**override))
    assert result["handled"] is False
    assert result["provider"].calls == []


def test_offer_not_available_without_packages_or_provider(tmp_path):
    assert aur_update_review_available([], options()) is False
    assert run_offer(tmp_path, [], [], [])["handled"] is False
    assert run_offer(
        tmp_path,
        [package()],
        ["y"],
        [],
        wrapper_provider=None,
    )["handled"] is False


# -- wrapper contract ------------------------------------------------------


def test_scan_only_argument_is_supported_by_the_wrapper():
    parsed = makepkg_wrapper.parse_args([AUR_SCAN_ONLY_ARGUMENT])
    assert parsed.scan_only is True
    assert parsed.makepkg_args == []
    assert AUR_SCAN_ONLY_ARGUMENT in makepkg_wrapper._BOOL_FLAGS


# -- guided build dependency pre-check -------------------------------------


class DependencyPacman:
    """Read-only pacman fake covering deptest, resolution and version query."""

    def __init__(self, installed=(), repo_missing=(), providers=None):
        self.installed = set(installed)
        self.repo_missing = set(repo_missing)
        self.providers = dict(providers or {})
        self.calls = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        if len(argv) >= 2 and argv[1] == "-T":
            lines = [dep for dep in argv[2:] if dep not in self.installed]
            return FakeCompleted(len(lines), "".join(line + "\n" for line in lines))
        if len(argv) >= 2 and argv[1] == "-S":
            dependency = argv[-1]
            if dependency in self.repo_missing:
                return FakeCompleted(1, "", f"error: target not found: {dependency}\n")
            return FakeCompleted(0, self.providers.get(dependency, dependency) + "\n")
        if len(argv) >= 2 and argv[1] == "-Q":
            name = argv[2]
            if name in self.installed:
                return FakeCompleted(0, f"{name} 1.0-1\n")
            return FakeCompleted(1, "")
        return FakeCompleted(0)

    def deptest_calls(self):
        return [call for call in self.calls if len(call) >= 2 and call[1] == "-T"]


class OnCallWrapperProvider(FakeWrapperProvider):
    """Wrapper fake that can model the side effects of a build step."""

    def __init__(self, results, on_call=None):
        super().__init__(results)
        self.on_call = on_call

    def __call__(self, arguments, cwd, stdout, stderr):
        result = super().__call__(arguments, cwd, stdout, stderr)
        if self.on_call is not None:
            self.on_call(list(arguments), Path(cwd))
        return result


def repository_runner(
    record,
    *,
    pkgbuilds=None,
    ls_remote_returncode=0,
    revision="b" * 40,
):
    contents = dict(pkgbuilds or {})

    def runner(argv, **kwargs):
        argv = list(argv)
        record.append((argv, kwargs))
        if "clone" in argv:
            target = Path(argv[-1])
            target.mkdir(parents=True, exist_ok=True)
            base = target.name.split(".", 1)[0]
            content = contents.get(base, f"pkgname={base}\npkgver=1\n")
            (target / "PKGBUILD").write_text(content, encoding="utf-8")
            return FakeCompleted(0)
        if "rev-parse" in argv:
            return FakeCompleted(0, revision + "\n")
        if "ls-remote" in argv:
            return FakeCompleted(ls_remote_returncode, "refs/heads/master\n")
        return FakeCompleted(1)

    return runner


def test_dependency_check_lists_repository_installable_dependencies(tmp_path):
    parent = (
        "pkgname=lib32-openal\npkgver=1\n"
        "makedepends=(\n cmake\n lib32-jack\n lib32-libpulse\n)\n"
    )
    pacman = DependencyPacman(providers={"lib32-jack": "lib32-jack2"})

    result = run_offer(
        tmp_path,
        [package(name="lib32-openal")],
        ["", ""],
        [WRAPPER_RESULT_OK, WRAPPER_RESULT_OK],
        runner=repository_runner([], pkgbuilds={"lib32-openal": parent}),
        pacman_runner=pacman,
    )

    assert (
        "will install missing build dependencies with sudo: "
        "cmake, lib32-jack, lib32-libpulse."
    ) in result["stdout"]
    assert [arguments for arguments, _cwd in result["provider"].calls] == [
        [AUR_SCAN_ONLY_ARGUMENT],
        list(AUR_BUILD_MAKEPKG_ARGUMENTS),
    ]


def test_missing_aur_dependency_is_built_first_after_consent(tmp_path):
    parent = (
        "pkgname=lib32-openal\npkgver=1\n"
        "makedepends=(\n cmake\n lib32-portaudio\n)\n"
    )
    dependency = "pkgname=lib32-portaudio\npkgver=1\n"
    pacman = DependencyPacman(
        installed={"cmake", "lib32-glibc"},
        repo_missing={"lib32-portaudio"},
    )

    def on_call(arguments, cwd):
        if arguments == list(AUR_BUILD_MAKEPKG_ARGUMENTS) and cwd.name.startswith(
            "lib32-portaudio."
        ):
            pacman.installed.add("lib32-portaudio")

    provider = OnCallWrapperProvider(
        [
            WRAPPER_RESULT_OK,
            WRAPPER_RESULT_OK,
            WRAPPER_RESULT_OK,
            WRAPPER_RESULT_OK,
        ],
        on_call=on_call,
    )
    result = run_offer(
        tmp_path,
        [package(name="lib32-openal")],
        ["", "", "", ""],
        [],
        wrapper_provider=provider,
        runner=repository_runner(
            [],
            pkgbuilds={"lib32-openal": parent, "lib32-portaudio": dependency},
        ),
        pacman_runner=pacman,
    )

    calls = [(arguments, cwd.name) for arguments, cwd in provider.calls]
    assert calls[0][1].startswith("lib32-openal.")
    assert [arguments for arguments, _name in calls] == [
        [AUR_SCAN_ONLY_ARGUMENT],
        [AUR_SCAN_ONLY_ARGUMENT],
        list(AUR_BUILD_MAKEPKG_ARGUMENTS),
        list(AUR_BUILD_MAKEPKG_ARGUMENTS),
    ]
    assert calls[1][1].startswith("lib32-portaudio.")
    assert calls[2][1] == calls[1][1]
    assert calls[3][1].startswith("lib32-openal.")
    assert (
        "Build dependency lib32-portaudio is not in your configured repositories; "
        "it is available in the AUR (https://aur.archlinux.org/packages/lib32-portaudio)."
    ) in result["stdout"]
    assert "Downloading lib32-portaudio (build dependency of lib32-openal)" in result["stdout"]
    assert "Installed lib32-portaudio 1.0-1." in result["stdout"]
    assert "build dependency of lib32-openal" in result["input"].prompts[2]
    assert "was not built" not in result["stderr"]


def test_declined_aur_dependency_stops_before_build_consent(tmp_path):
    parent = (
        "pkgname=lib32-openal\npkgver=1\n"
        "makedepends=(lib32-portaudio)\n"
    )
    pacman = DependencyPacman(repo_missing={"lib32-portaudio"})

    result = run_offer(
        tmp_path,
        [package(name="lib32-openal")],
        ["", "n"],
        [WRAPPER_RESULT_OK],
        runner=repository_runner([], pkgbuilds={"lib32-openal": parent}),
        pacman_runner=pacman,
    )

    assert [arguments for arguments, _cwd in result["provider"].calls] == [
        [AUR_SCAN_ONLY_ARGUMENT],
    ]
    assert "Skipped the guided build of lib32-portaudio." in result["stdout"]
    assert (
        "lib32-openal was not built: makepkg installs missing build dependencies through pacman"
        in result["stderr"]
    )
    assert "Nothing was installed." in result["stderr"]


def test_unconfirmed_aur_dependency_stops_without_aur_claim(tmp_path):
    parent = (
        "pkgname=lib32-openal\npkgver=1\n"
        "makedepends=(lib32-portaudio)\n"
    )
    pacman = DependencyPacman(repo_missing={"lib32-portaudio"})

    result = run_offer(
        tmp_path,
        [package(name="lib32-openal")],
        [""],
        [WRAPPER_RESULT_OK],
        runner=repository_runner(
            [],
            pkgbuilds={"lib32-openal": parent},
            ls_remote_returncode=1,
        ),
        pacman_runner=pacman,
    )

    assert (
        "Build dependency lib32-portaudio is not available in your configured repositories."
        in result["stdout"]
    )
    assert "available in the AUR" not in result["stdout"]
    assert len(result["input"].prompts) == 1
    assert "was not built" in result["stderr"]


def test_dynamic_dependency_arrays_disable_the_check(tmp_path):
    parent = (
        "pkgname=lib32-openal\npkgver=1\n"
        "makedepends=(${_deps[@]})\n"
    )
    pacman = DependencyPacman()

    result = run_offer(
        tmp_path,
        [package(name="lib32-openal")],
        ["", ""],
        [WRAPPER_RESULT_OK, WRAPPER_RESULT_OK],
        runner=repository_runner([], pkgbuilds={"lib32-openal": parent}),
        pacman_runner=pacman,
    )

    assert pacman.deptest_calls() == []
    assert "will install missing build dependencies" not in result["stdout"]
    assert [arguments for arguments, _cwd in result["provider"].calls] == [
        [AUR_SCAN_ONLY_ARGUMENT],
        list(AUR_BUILD_MAKEPKG_ARGUMENTS),
    ]


def test_dependency_chain_limit_stops_recursive_offers(tmp_path):
    parent = (
        "pkgname=lib32-openal\npkgver=1\n"
        "makedepends=(lib32-portaudio)\n"
    )
    dependency = (
        "pkgname=lib32-portaudio\npkgver=1\n"
        "makedepends=(lib32-openal)\n"
    )
    pacman = DependencyPacman(repo_missing={"lib32-portaudio", "lib32-openal"})

    result = run_offer(
        tmp_path,
        [package(name="lib32-openal")],
        ["", ""],
        [WRAPPER_RESULT_OK, WRAPPER_RESULT_OK],
        runner=repository_runner(
            [],
            pkgbuilds={"lib32-openal": parent, "lib32-portaudio": dependency},
        ),
        pacman_runner=pacman,
    )

    assert [arguments for arguments, _cwd in result["provider"].calls] == [
        [AUR_SCAN_ONLY_ARGUMENT],
        [AUR_SCAN_ONLY_ARGUMENT],
    ]
    assert "lib32-portaudio was not built" in result["stderr"]
    assert "dependency chain limit was reached" in result["stderr"]
    assert "lib32-openal was not built" in result["stderr"]


def test_check_guided_build_dependencies_classifies_each_result(tmp_path):
    pacman = DependencyPacman(installed={"git"}, repo_missing={"lib32-portaudio"})

    check = check_guided_build_dependencies(
        "makedepends=(\n  git\n  cmake\n  lib32-jack\n  lib32-portaudio\n)\n",
        work_root=tmp_path / "root",
        pacman_runner=pacman,
        pacman_capture=fake_pacman_capture,
        pacman_revalidate=lambda _executable: None,
        runner=repository_runner([], ls_remote_returncode=0),
        which=lambda name: "/usr/bin/" + name,
        tool_capture=fake_git_capture,
        tool_revalidate=RevalidateRecorder(),
    )

    assert check is not None
    assert check.missing == ("cmake", "lib32-jack", "lib32-portaudio")
    assert check.repo_installable == ("cmake", "lib32-jack")
    assert check.unresolved == ("lib32-portaudio",)
    assert check.aur_only == ("lib32-portaudio",)


def test_check_guided_build_dependencies_reports_unknown_for_doubt(tmp_path):
    pacman = DependencyPacman()
    arguments = {
        "pacman_runner": pacman,
        "pacman_capture": fake_pacman_capture,
        "pacman_revalidate": lambda _executable: None,
        "runner": repository_runner([], ls_remote_returncode=0),
        "which": lambda name: "/usr/bin/" + name,
        "tool_capture": fake_git_capture,
        "tool_revalidate": RevalidateRecorder(),
    }

    assert check_guided_build_dependencies(
        "makedepends=(${_deps[@]})\n",
        work_root=tmp_path / "root",
        **arguments,
    ) is None

    def failing_runner(argv, **kwargs):
        return FakeCompleted(1, "", "error: failed to init transaction\n")

    assert check_guided_build_dependencies(
        "makedepends=(cmake)\n",
        work_root=tmp_path / "root",
        **{**arguments, "pacman_runner": failing_runner},
    ) is None


@pytest.mark.parametrize("dependency", ["lib32-portaudio", "cmake"])
def test_missing_dependency_without_any_problem_is_not_reported(tmp_path, dependency):
    pacman = DependencyPacman(installed={dependency})

    check = check_guided_build_dependencies(
        f"makedepends=({dependency})\n",
        work_root=tmp_path / "root",
        pacman_runner=pacman,
        pacman_capture=fake_pacman_capture,
        pacman_revalidate=lambda _executable: None,
        runner=repository_runner([], ls_remote_returncode=0),
        which=lambda name: "/usr/bin/" + name,
        tool_capture=fake_git_capture,
        tool_revalidate=RevalidateRecorder(),
    )

    assert check is not None
    assert check.missing == ()
    assert check.repo_installable == ()
    assert check.unresolved == ()


def test_read_captured_pkgbuild_is_bounded(tmp_path, monkeypatch):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\n", encoding="utf-8")

    assert read_captured_pkgbuild(pkgbuild) == "pkgname=demo\n"
    assert read_captured_pkgbuild(tmp_path / "missing") is None
    assert read_captured_pkgbuild(tmp_path) is None

    monkeypatch.setattr("aurascan.core.aur_update_review.MAX_CAPTURED_PKGBUILD_BYTES", 4)
    assert read_captured_pkgbuild(pkgbuild) is None
