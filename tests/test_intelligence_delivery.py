"""Delivery contract tests: no network, root mutation, or host service calls."""

import configparser
from contextlib import contextmanager
import fcntl
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError
from urllib.request import ProxyHandler, Request

import pytest

from aurascan.core import intelligence_cli as cli
from aurascan.core import intelligence_transport as transport
from aurascan.core.intelligence import IntelligenceError, bundled_snapshot


ROOT = Path(__file__).resolve().parents[1]
BASE = "https://github.com/example/aurascan-intelligence/releases/latest/download"


def forbidden(*_args, **_kwargs):
    raise AssertionError("unexpected authority or network operation")


def test_status_is_offline_and_identifies_unconfigured_channel(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_intelligence_snapshot", bundled_snapshot)
    monkeypatch.setattr(cli, "_systemctl", forbidden)
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    assert cli.run_intelligence(["status", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["source"] == "bundled"
    assert result["update_channel"] == "unconfigured"
    assert result["schema_version"] == "1.0"


def test_dispatch_never_loads_dotenv_or_ai_config(monkeypatch):
    import aurascan.cli as main
    called = []
    monkeypatch.setattr(main, "load_command_environment", forbidden)
    monkeypatch.setattr(main, "load_env", forbidden)
    monkeypatch.setattr(cli, "run_intelligence", lambda args: called.append(args) or 0)
    with pytest.raises(SystemExit) as stopped:
        main.main(["intelligence", "status"])
    assert stopped.value.code == 0
    assert called == [["status"]]


@pytest.mark.parametrize("arguments", [["update"], ["import", "/tmp/example"],
                                       ["auto-update", "enable"], ["auto-update", "disable"]])
def test_mutations_require_admin_before_services_or_input_reads(monkeypatch, capsys, arguments):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "_systemctl", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    assert cli.run_intelligence(arguments) == 1
    assert "administrative authorization required" in capsys.readouterr().err


@pytest.mark.parametrize("arguments", [["update"], ["import", "/missing"], ["auto-update", "enable"]])
def test_unconfigured_trust_prevents_public_updates_before_action(monkeypatch, capsys, arguments):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_systemctl", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    assert cli.run_intelligence(arguments) == 1
    assert "not configured" in capsys.readouterr().err


def test_disabling_timer_needs_no_configured_feed(monkeypatch):
    called = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "assert_production_trust_configured", forbidden)
    monkeypatch.setattr(cli, "_systemctl", lambda args: called.append(args))
    assert cli.run_intelligence(["auto-update", "disable"]) == 0
    assert called == [["disable", "--now", cli.UPDATE_TIMER]]


def test_update_and_offline_import_use_distinct_fixed_services(monkeypatch, tmp_path):
    calls = []
    @contextmanager
    def stage(path):
        calls.append(("capture", path))
        yield
        calls.append(("release-import-lock",))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "assert_production_trust_configured", lambda: None)
    monkeypatch.setattr(cli, "assert_feed_configured", lambda: None)
    monkeypatch.setattr(cli, "load_intelligence_snapshot", bundled_snapshot)
    monkeypatch.setattr(cli, "_systemctl", lambda args: calls.append(("service", args)))
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    monkeypatch.setattr(cli, "stage_offline_bundle", stage)
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    assert cli.run_intelligence(["update"]) == 0
    assert calls.pop() == ("service", ["start", cli.ACTIVATION_SERVICE])
    assert cli.run_intelligence(["import", str(tmp_path)]) == 0
    assert calls == [("capture", tmp_path), ("service", ["start", cli.IMPORT_SERVICE]),
                     ("release-import-lock",)]


@pytest.mark.parametrize("arguments", [["status", "--key", "attacker"],
                                       ["update", "--feed", BASE], ["import", "/tmp", "--skip-verification"],
                                       ["_activate"], ["_fetch"]])
def test_public_cli_has_no_alternate_trust_or_private_service_controls(arguments):
    with pytest.raises(SystemExit) as stopped:
        cli.run_intelligence(arguments)
    assert stopped.value.code != 0


def test_service_fetch_refuses_root_and_wrong_account(monkeypatch):
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    assert cli._service_main(["_fetch"]) == 1
    monkeypatch.setattr(cli.os, "geteuid", lambda: 123)
    monkeypatch.setattr(cli.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="unrelated"))
    assert cli._service_main(["_fetch"]) == 1


def test_systemctl_uses_fixed_tool_clean_environment_and_no_shell(monkeypatch):
    captured = []
    tool = SimpleNamespace(path="/usr/bin/systemctl")
    monkeypatch.setattr(cli, "capture_trusted_system_tool", lambda *args, **kwargs: tool)
    monkeypatch.setattr(cli, "revalidate_trusted_system_tool", lambda value: captured.append(value))
    monkeypatch.setattr(cli, "run_bounded_trusted_tool", lambda args, **kwargs:
                        captured.append((args, kwargs)) or SimpleNamespace(returncode=0))
    monkeypatch.setenv("AURASCAN_AI_KEY", "fake-secret")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/tmp/fake-bus")
    cli._systemctl(["start", cli.ACTIVATION_SERVICE])
    assert captured[0] is tool
    args, options = captured[1]
    assert args[0] == "/usr/bin/systemctl"
    assert "--no-ask-password" in args
    assert "shell" not in options
    assert "AURASCAN_AI_KEY" not in options["env"]
    assert "DBUS_SYSTEM_BUS_ADDRESS" not in options["env"]
    assert options["cwd"] == "/" and options["timeout"] <= 240


@pytest.mark.parametrize("base", ["", "http://github.com/a/b/releases/latest/download",
                                  "https://github.com.evil.invalid/a/b/releases/latest/download",
                                  "https://user@github.com/a/b/releases/latest/download",
                                  "https://github.com/a/b/releases/latest/download?token=fake",
                                  "https://github.com/a/../releases/latest/download"])
def test_feed_configuration_rejects_non_fixed_github_release_paths(base):
    with pytest.raises(IntelligenceError):
        transport._feed_identity(base)


@pytest.mark.parametrize("url", ["http://github.com/example/aurascan-intelligence/releases/download/v1/manifest.json",
                                 "https://github.com/other/repo/releases/download/v1/manifest.json",
                                 "https://github.com/example/aurascan-intelligence/releases/download/v1/other.json",
                                 "https://user@release-assets.githubusercontent.com/github-production-release-asset/1/a",
                                 "https://release-assets.githubusercontent.com.evil.invalid/github-production-release-asset/1/a",
                                 "https://example.invalid/manifest.json",
                                 "https://release-assets.githubusercontent.com/github-production-release-asset/../private"])
def test_redirects_cannot_expand_authority(url):
    redirects = transport._ReleaseRedirects("/example/aurascan-intelligence/releases/", "manifest.json")
    with pytest.raises(IntelligenceError):
        redirects.redirect_request(Request(BASE + "/manifest.json"), None, 302, "", {}, url)


def test_release_redirects_are_bounded_and_rebuild_get_headers():
    redirects = transport._ReleaseRedirects("/example/aurascan-intelligence/releases/", "manifest.json")
    request = Request(BASE + "/manifest.json", headers={"Authorization": "fake-secret"})
    destination = "https://release-assets.githubusercontent.com/github-production-release-asset/1/abc?token=fake"
    for _ in range(transport.MAX_REDIRECTS):
        rewritten = redirects.redirect_request(request, None, 302, "", {}, destination)
        assert rewritten.get_method() == "GET"
        assert "Authorization" not in rewritten.headers
    with pytest.raises(IntelligenceError):
        redirects.redirect_request(request, None, 302, "", {}, destination)


def test_download_disables_proxies_bounds_bytes_and_suppresses_url_errors():
    handlers = []

    class Response(io.BytesIO):
        status = 200
        headers = {}

    def factory(*values):
        handlers.extend(values)
        return SimpleNamespace(open=lambda *_a, **_k: Response(b"abcd"))

    result = transport._download(BASE, "manifest.json", 4, transport.time.monotonic() + 30,
                                 opener_factory=factory)
    assert result == b"abcd"
    assert any(isinstance(value, ProxyHandler) and value.proxies == {} for value in handlers)
    with pytest.raises(IntelligenceError):
        transport._download(BASE, "manifest.json", 3, transport.time.monotonic() + 30,
                            opener_factory=factory)

    def fail(*_a, **_k):
        raise URLError("https://example.invalid/?token=fake-secret")

    with pytest.raises(IntelligenceError) as failure:
        transport._download(BASE, "manifest.json", 4, transport.time.monotonic() + 30,
                            opener_factory=lambda *args: SimpleNamespace(open=fail))
    assert "fake-secret" not in str(failure.value)


def test_staging_fetch_never_activates_and_preserves_existing_bundle_on_network_failure(tmp_path):
    directory = tmp_path / "stage"
    directory.mkdir(mode=0o700)
    calls = []

    def download(base, name, limit, deadline):
        calls.append(name)
        return name.encode("ascii")

    transport.fetch_bundle(base=BASE, staging=directory, downloader=download)
    assert set(calls) == set(transport.ASSET_LIMITS)
    for name in calls:
        assert (directory / name).read_bytes() == name.encode("ascii")
    assert not (directory / "active.json").exists()

    def fail(*args):
        raise IntelligenceError("download refused")

    with pytest.raises(IntelligenceError):
        transport.fetch_bundle(base=BASE, staging=directory, downloader=fail)
    assert (directory / "manifest.json").read_bytes() == b"manifest.json"


def test_staging_refuses_symlinks_and_hostile_permissions(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(stage, target_is_directory=True)
    with pytest.raises(OSError):
        transport.fetch_bundle(base=BASE, staging=linked, downloader=forbidden)
    stage.chmod(0o777)
    with pytest.raises(IntelligenceError):
        transport.fetch_bundle(base=BASE, staging=stage, downloader=forbidden)
    stage.chmod(0o700)
    (stage / ".fetch.lock").symlink_to(tmp_path / "unrelated")
    with pytest.raises(IntelligenceError):
        transport.fetch_bundle(base=BASE, staging=stage, downloader=forbidden)
    assert not (tmp_path / "unrelated").exists()


def test_concurrent_fetch_cannot_replace_staging_while_lock_is_held(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    lock_fd = os.open(str(stage / ".fetch.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(IntelligenceError, match="already running"):
            transport.fetch_bundle(base=BASE, staging=stage, downloader=forbidden)
        assert not (stage / "manifest.json").exists()
    finally:
        os.close(lock_fd)


def test_download_bounds_truncation_encoding_and_deadline():
    class Response(io.BytesIO):
        status = 200

    for headers, data in (({"Content-Length": "10"}, b"tiny"),
                          ({"Content-Encoding": "gzip"}, b"data"),
                          ({"Content-Length": "99999999"}, b"data")):
        def factory(*_args):
            response = Response(data)
            response.headers = headers
            return SimpleNamespace(open=lambda *_a, **_k: response)
        with pytest.raises(IntelligenceError):
            transport._download(BASE, "manifest.json", 16, transport.time.monotonic() + 30,
                                opener_factory=factory)
    with pytest.raises(IntelligenceError, match="deadline"):
        transport._download(BASE, "manifest.json", 16, transport.time.monotonic() - 1,
                            opener_factory=lambda *_args: SimpleNamespace(open=forbidden))


def _unit(name):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(ROOT / "aurascan/assets" / name)
    return parser


def test_service_definitions_enforce_separate_privileges_and_disabled_timer():
    fetch = _unit("aurascan-intelligence-fetch.service")
    activate = _unit("aurascan-intelligence-activate.service")
    offline = _unit("aurascan-intelligence-import.service")
    timer = _unit("aurascan-intelligence-update.timer")
    assert fetch["Service"]["User"] == cli.FETCH_ACCOUNT
    assert activate["Service"]["User"] == "root"
    assert fetch["Service"]["StateDirectory"] != activate["Service"]["StateDirectory"]
    assert activate["Service"]["PrivateNetwork"] == "yes"
    assert activate["Service"]["IPAddressDeny"] == "any"
    assert activate["Service"]["RestrictAddressFamilies"] == "AF_UNIX"
    assert activate["Unit"]["Requires"] == "aurascan-intelligence-fetch.service"
    assert "Requires" not in offline["Unit"]
    assert offline["Service"]["PrivateNetwork"] == "yes"
    assert offline["Service"]["IPAddressDeny"] == "any"
    assert "_activate-import" in offline["Service"]["ExecStart"]
    for unit in (fetch, activate, offline):
        assert unit["Service"]["ExecStart"].startswith("/usr/bin/env -i ")
        assert "python -I -m aurascan.core.intelligence_cli" in unit["Service"]["ExecStart"]
        assert unit["Service"]["ProtectHome"] == "yes"
        assert unit["Service"]["Restart"] == "no"
        assert int(unit["Service"]["TimeoutStartSec"]) <= 110
    assert timer["Timer"]["OnCalendar"] == "daily"
    assert timer["Timer"]["RandomizedDelaySec"] == "4h"
    assert "disable " + cli.UPDATE_TIMER in (ROOT / "aurascan/assets/aurascan-intelligence.preset").read_text()
    install = (ROOT / "packaging/arch/aurascan.install").read_text()
    assert "intelligence" not in install


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_redirect_responses_are_closed_without_reading_unbounded_bodies(code):
    from email.message import Message

    class RedirectBody:
        closed = False

        def read(self, *_args):
            pytest.fail("redirect bodies must never be read, even with no Content-Length")

        def close(self):
            self.closed = True

    headers = Message()
    headers["Location"] = "/example/aurascan-intelligence/releases/download/v1/manifest.json"
    headers["Content-Length"] = "99999999999999999999"
    response = RedirectBody()
    calls = []
    sentinel = object()
    handler = transport._ReleaseRedirects("/example/aurascan-intelligence/releases/", "manifest.json",
                                          transport.time.monotonic() + 4)

    def next_request(request, *, timeout):
        assert response.closed
        calls.append((request, timeout))
        return sentinel

    handler.parent = SimpleNamespace(open=next_request)
    method = getattr(handler, "http_error_" + str(code))
    assert method(Request(BASE + "/manifest.json"), response, code, "redirect", headers) is sentinel
    request, timeout = calls[0]
    assert request.full_url == "https://github.com/example/aurascan-intelligence/releases/download/v1/manifest.json"
    assert request.get_method() == "GET" and 0 < timeout <= 4


@pytest.mark.parametrize("locations", [[], ["https://example.invalid/manifest.json"],
                                       ["/one", "/two"], ["/a" + "x" * 4096],
                                       ["https://github.com/\nexample/repo"], ["https://github.com/é"]])
def test_rejected_redirect_closes_response_without_reading_body(locations):
    from email.message import Message

    response = SimpleNamespace(read=forbidden, close=lambda: setattr(response, "closed", True), closed=False)
    headers = Message()
    for location in locations:
        headers["Location"] = location
    handler = transport._ReleaseRedirects("/example/aurascan-intelligence/releases/", "manifest.json")
    handler.parent = SimpleNamespace(open=forbidden)
    with pytest.raises(IntelligenceError):
        handler.http_error_302(Request(BASE + "/manifest.json"), response, 302, "redirect", headers)
    assert response.closed


def test_redirect_budget_is_the_original_operation_deadline(monkeypatch):
    from email.message import Message

    clock = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: clock[0])
    handler = transport._ReleaseRedirects("/example/aurascan-intelligence/releases/", "manifest.json", 105.0)
    headers = Message()
    headers["Location"] = "/example/aurascan-intelligence/releases/download/v1/manifest.json"
    timeouts = []
    handler.parent = SimpleNamespace(open=lambda request, *, timeout: timeouts.append(timeout))
    request = Request(BASE + "/manifest.json")
    for instant, expected in [(101.0, 4.0), (104.0, 1.0)]:
        clock[0] = instant
        response = SimpleNamespace(read=forbidden, close=lambda: None)
        handler.http_error_302(request, response, 302, "redirect", headers)
        assert timeouts[-1] == expected
    clock[0] = 105.0
    response = SimpleNamespace(read=forbidden, close=lambda: setattr(response, "closed", True), closed=False)
    with pytest.raises(IntelligenceError):
        handler.http_error_302(request, response, 302, "redirect", headers)
    assert response.closed and len(timeouts) == 2
