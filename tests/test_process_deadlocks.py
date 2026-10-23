from io import StringIO
from pathlib import Path

from aurascan import setup_wizard
from aurascan.core.process_deadlocks import (
    cached_downgrade_path,
    detect_wait_then_read_deadlocks,
)
from aurascan.setup_wizard import _hung_application_check, build_doctor_parser


def _write_proc_entry(root: Path, pid: int, comm: str, ppid: int, start_ticks: int, wchan: str) -> Path:
    entry = root / str(pid)
    entry.mkdir(parents=True)
    fields = [
        "S",
        str(ppid),
        "1",
        "1",
        "0",
        "-1",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "1",
        "0",
        str(start_ticks),
    ]
    (entry / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields) + "\n")
    (entry / "wchan").write_text(wchan + "\n")
    return entry


def test_detects_lsmod_wait_then_read_deadlock(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "uptime").write_text("100.0 10.0\n")
    parent = _write_proc_entry(proc, 100, "goverlay", 1, 0, "x64_sys_wait4.cold")
    (parent / "exe").symlink_to("/usr/lib/goverlay")
    _write_proc_entry(proc, 101, "lsmod", 100, 0, "anon_pipe_write")

    deadlocks = detect_wait_then_read_deadlocks(proc_root=proc, min_age_seconds=0)

    assert len(deadlocks) == 1
    assert deadlocks[0].parent_pid == 100
    assert deadlocks[0].parent_comm == "goverlay"
    assert deadlocks[0].parent_executable == "/usr/lib/goverlay"
    assert deadlocks[0].child_pid == 101
    assert deadlocks[0].child_wchan == "anon_pipe_write"


def test_ignores_lsmod_that_is_not_blocked_on_a_pipe(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "uptime").write_text("100.0 10.0\n")
    _write_proc_entry(proc, 100, "goverlay", 1, 0, "x64_sys_wait4.cold")
    _write_proc_entry(proc, 101, "lsmod", 100, 0, "do_syscall_64")

    assert detect_wait_then_read_deadlocks(proc_root=proc, min_age_seconds=0) == []


def test_cached_downgrade_path_selects_newest_older_version(tmp_path):
    older = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    older.write_bytes(b"older")
    newer = tmp_path / "demo-1.1-1-x86_64.pkg.tar.zst"
    newer.write_bytes(b"newer")
    installed = tmp_path / "demo-2.0-1-x86_64.pkg.tar.zst"
    installed.write_bytes(b"installed")

    result = cached_downgrade_path(
        package="demo",
        installed_version="2.0-1",
        cache_root=tmp_path,
        version_compare=lambda installed_version, candidate: (
            1 if installed_version == "2.0-1" and candidate.startswith("1.") else -1
        ),
    )

    assert result == newer


def test_hung_application_check_reports_deadlock_fixture(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "uptime").write_text("100.0 10.0\n")
    parent = _write_proc_entry(proc, 100, "goverlay", 1, 0, "x64_sys_wait4.cold")
    (parent / "exe").symlink_to("/usr/lib/goverlay")
    _write_proc_entry(proc, 101, "lsmod", 100, 0, "anon_pipe_write")

    check = _hung_application_check(proc_root=proc)

    assert check.status == "warn"
    assert "process deadlock, not a missing library" in check.message
    assert check.details["count"] == 1


def test_doctor_parser_accepts_hung_application_repair_flag():
    args = build_doctor_parser().parse_args(["--fix-hung-apps"])

    assert args.fix_hung_apps is True


def test_run_doctor_fix_hung_apps_passes_explicit_stderr(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(setup_wizard, "build_doctor_checks", lambda **_kwargs: [])
    monkeypatch.setattr(
        setup_wizard,
        "run_doctor_hung_application_repair",
        lambda **kwargs: captured.update(kwargs) or 0,
    )
    stdout = StringIO()
    stderr = StringIO()

    status = setup_wizard.run_doctor(
        ["--fix-hung-apps"],
        stdout=stdout,
        stderr=stderr,
        proc_root=tmp_path / "proc",
    )

    assert status == 0
    assert captured["stderr"] is stderr
    assert captured["proc_root"] == tmp_path / "proc"
