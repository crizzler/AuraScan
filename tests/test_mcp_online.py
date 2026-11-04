"""``security_audit_online``: the sixth tool, the B4 no-write proof and the fetch failure ladder.

Two things are being pinned here. First, the online audit must never disturb the offline one: the
refresh lives in the returned report, no file under ``XDG_STATE_HOME`` is created or changed, and a
later ``security_audit`` call still reports ``bundled`` (or the untouched cache). Second, the network
half must fail in fixed tokens and never in exception text, and the 110 s budget must be a real bound
*inside the fetch* — the ``TimeoutExpired`` arm exists because the wrapper's catch-all would otherwise
turn the alarm into an ``unknown`` note and let the audit run on.

No test touches the internet: loopback servers and stubs only. ``arch-audit`` is not installed on the
host, so anything that cares puts a shim on ``PATH``. A campaign feed URL must be ``https://`` to load,
so every loopback case rewrites the scheme to ``http://`` in a thin ``strict_urlopen`` wrapper — the
opener is still the real one, the redirect handler is still the real one.
"""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen as plain_urlopen

import pytest

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from aurascan.core import security_audit as core  # noqa: E402
from aurascan.core.security_audit import (  # noqa: E402
    MAX_CAMPAIGN_BYTES, RedirectRejected, strict_urlopen,
)
from aurascan.mcp import registry  # noqa: E402
from aurascan.mcp.tools import security_audit as offline_tool  # noqa: E402
from aurascan.mcp.tools import security_audit_online as online_tool  # noqa: E402
from helpers.mcp_client import Loop, spawn  # noqa: E402

ONLINE = "security_audit_online"
FIRST_FIVE = (
    "scan_content", "scan_path", "audit_agent_config", "security_audit", "verify_evidence",
)
MANIFEST = "aur-campaign-2026-06-11.json"
PACKAGES = "aur-campaign-2026-06-11-packages.txt"
SOURCE_URL = "https://example.invalid/aurvulnlist20260611.txt"

SURFACE = Path(__file__).resolve().parent / "fixtures" / "mcp" / "tool_surface.json"


# -- fixtures and harnesses ---------------------------------------------- #


def _root(tmp_path):
    root = tmp_path / "root"
    root.mkdir(exist_ok=True)
    return root


def _state(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    return state


def _root_patch(tmp_path, monkeypatch):
    """Both handlers get the same tmp root so the real host is never the subject."""
    here = _root(tmp_path)
    monkeypatch.setattr(online_tool, "_ROOT", here)
    monkeypatch.setattr(offline_tool, "_ROOT", here)
    return here


def _write_campaign(tmp_path, url=SOURCE_URL, names=("package-a", "package-b")):
    """A loadable manifest/list pair; only ``_asset_path`` needs patching to use it."""
    payload = ("\n".join(names) + "\n").encode("utf-8")
    manifest = {
        "schema_version": "1.0",
        "campaign_id": "AUR-TEST",
        "title": "test campaign",
        "source_url": url,
        "official_reference": "https://archlinux.org/news/active-aur-malicious-packages-incident/",
        "source_kind": "community-curated",
        "window_start": "2026-06-09",
        "window_end": "2026-06-14",
        "payload_indicators": ["lockfile-js"],
        "package_count": len(names),
        "package_list_sha256": core.hashlib.sha256(payload).hexdigest(),
        "retrieved_at": "2026-07-27T14:15:00+00:00",
    }
    directory = tmp_path / "campaign"
    directory.mkdir(exist_ok=True)
    (directory / MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    (directory / PACKAGES).write_bytes(payload)
    return directory / MANIFEST, directory / PACKAGES


def _point_assets(tmp_path, monkeypatch, url=SOURCE_URL, names=("package-a", "package-b")):
    manifest, packages = _write_campaign(tmp_path, url=url, names=names)
    monkeypatch.setattr(
        core, "_asset_path",
        lambda name: manifest if name == MANIFEST else packages,
    )
    return manifest


def _http_rewrite(monkeypatch):
    """Keep the real opener and handler; only the scheme is rewritten for a plaintext server."""
    real = core.strict_urlopen

    def wrapper(request, timeout=core.DEFAULT_FEED_TIMEOUT):
        request.full_url = request.full_url.replace("https://", "http://", 1)
        return real(request, timeout=timeout)

    monkeypatch.setattr(online_tool, "strict_urlopen", wrapper)


class FakeResponse(object):
    def __init__(self, payload, url=SOURCE_URL, headers=None):
        self.payload = payload
        self.url = url
        self.headers = headers if headers is not None else {}

    def geturl(self):
        return self.url

    def read(self, limit=-1):
        return self.payload if limit is None or limit < 0 else self.payload[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class StubFetch(object):
    """urlopen-shaped stub; ``behaviour`` is a payload or an exception instance."""

    def __init__(self, behaviour, url=SOURCE_URL):
        self.behaviour = behaviour
        self.url = url
        self.calls = 0

    def __call__(self, request, timeout):
        self.calls += 1
        if isinstance(self.behaviour, BaseException):
            raise self.behaviour
        if isinstance(self.behaviour, FakeResponse):
            return self.behaviour
        return FakeResponse(self.behaviour, self.url)


def _install_fetch(monkeypatch, behaviour, url=SOURCE_URL):
    stub = StubFetch(behaviour, url=url)
    monkeypatch.setattr(online_tool, "strict_urlopen", stub)
    return stub


def _call(tool, arguments=None, budgets=None):
    loop = Loop(("/tmp",), budgets=budgets)
    loop.call(tool, arguments or {})
    message = loop.only()
    return json.loads(message["result"]["content"][0]["text"]), message["result"]["isError"]


def _shim(path, script):
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
    return path


class _Result(object):
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


# -- surface and schema --------------------------------------------------- #


def test_111_sixth_tool_is_last_and_stays_out_of_the_profile(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        names = [tool["name"] for tool in client.read()["result"]["tools"]]

    assert tuple(names[:5]) == FIRST_FIVE
    assert names[5:] == [ONLINE]

    text = (Path(__file__).resolve().parent / "fixtures" / "mcp" / "registration.yaml").read_text(
        encoding="utf-8"
    )
    include = [line for line in text.splitlines() if line.strip().startswith("include:")]
    assert len(include) == 1
    assert include[0].count(",") == 3
    assert ONLINE not in include[0]
    allowlist = [line for line in text.splitlines() if line.strip().startswith("- mcp:")]
    assert len(allowlist) == 4
    assert not any(ONLINE in line for line in allowlist)


def test_112_sixth_annotation_triple_is_truthful_and_the_rest_are_unchanged(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        tools = client.read()["result"]["tools"]

    def triple(tool):
        annotations = tool["annotations"]
        return (
            annotations["readOnlyHint"],
            annotations["destructiveHint"],
            annotations["openWorldHint"],
        )

    assert triple(tools[5]) == (False, False, True)
    for tool in tools[:5]:
        assert triple(tool) == (True, False, False), tool["name"]
    surface = json.loads(SURFACE.read_text(encoding="utf-8"))
    assert [entry["name"] for entry in surface] == list(FIRST_FIVE) + [ONLINE]
    for tool, expected in zip(tools, surface):
        assert tool["annotations"] == expected["annotations"]


def test_113_schema_is_the_four_projection_fields(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        schema = client.read()["result"]["tools"][5]["inputSchema"]

    assert set(schema["properties"]) == {
        "refresh", "include_arch_audit", "max_findings", "include_evidence",
    }
    assert "required" not in schema
    assert "offline" not in schema["properties"]
    assert schema["additionalProperties"] is False
    defaults = {name: rule["default"] for name, rule in schema["properties"].items()}
    assert defaults == {
        "refresh": True, "include_arch_audit": True, "max_findings": 100, "include_evidence": False,
    }


def test_114_invalid_arguments_keep_the_session(tmp_path):
    loop = Loop(("/tmp",))
    for index, arguments in enumerate(
        ({"max_findings": 0}, {"max_findings": 501}, {"offline": True}, {"refresh": "yes"})
    ):
        loop.call(ONLINE, arguments)
        body = json.loads(loop.lines()[-1]["result"]["content"][0]["text"])
        assert body["error"]["code"] == "invalid_arguments", arguments
        assert loop.lines()[-1]["result"]["isError"] is True
    loop.feed({"jsonrpc": "2.0", "method": "ping", "id": 99})
    assert loop.lines()[-1]["result"] == {}


def test_115_budget_is_110_and_under_the_client_timeout():
    assert list(registry.TOOLS_BY_NAME)[-1] == ONLINE
    assert len(registry.TOOLS_BY_NAME) == 6
    assert registry.TOOLS_BY_NAME[ONLINE].budget == 110 < 120
    assert registry.TOOLS_BY_NAME[ONLINE].annotations is registry._ONLINE_ANNOTATIONS


# -- B4: never persist ---------------------------------------------------- #


def test_116_online_refresh_leaves_the_offline_result_bundled(tmp_path, monkeypatch):
    state = _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)
    _install_fetch(monkeypatch, b"remote-package\n")

    body, is_error = _call(ONLINE, {"refresh": True})
    assert is_error is False
    assert body["refresh"]["status"] == "refreshed"
    assert body["campaign"]["data_origin"] == "refreshed"
    assert body["refresh"]["persisted"] is False

    offline, is_error = _call("security_audit", {})
    assert is_error is False
    assert offline["campaign"]["data_origin"] == "bundled"

    assert os.listdir(str(state)) == []


def test_117_the_tool_passes_the_no_write_pin(tmp_path, monkeypatch):
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    manifest = _point_assets(tmp_path, monkeypatch)
    seen = {}

    def recorder(campaign, **kwargs):
        seen.update(kwargs)
        seen["called"] = True
        return campaign

    monkeypatch.setattr(core, "refresh_campaign_intel", recorder)
    _install_fetch(monkeypatch, b"remote-package\n")

    body, is_error = _call(ONLINE, {"refresh": True})

    assert is_error is False
    assert seen["called"] is True
    assert seen["persist_refresh"] is False
    assert seen["state_root"] is None
    assert body["refresh"]["persisted"] is False
    assert Path(manifest).is_file()


def test_118_a_seeded_cache_is_neither_changed_nor_ignored(tmp_path, monkeypatch):
    state = _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)
    _install_fetch(monkeypatch, b"remote-package\n")

    cache_dir = state / "aurascan" / "security-intel"
    cache_dir.mkdir(parents=True)
    cached = b"cached-package\n"
    list_path = cache_dir / PACKAGES
    meta_path = cache_dir / (PACKAGES + ".meta.json")
    list_path.write_bytes(cached)
    meta_path.write_text(
        json.dumps({
            "schema_version": "1.0",
            "source_url": SOURCE_URL,
            "sha256": core.hashlib.sha256(cached).hexdigest(),
            "retrieved_at": "2026-07-01T00:00:00+00:00",
            "package_count": 1,
        }),
        encoding="utf-8",
    )
    for path in (list_path, meta_path):
        path.chmod(0o600)
    before = {
        path: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
        for path in (list_path, meta_path)
    }

    body, is_error = _call(ONLINE, {"refresh": True})
    assert is_error is False
    assert body["campaign"]["data_origin"] == "refreshed"
    for path, snapshot in before.items():
        assert (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) == snapshot

    offline, is_error = _call("security_audit", {})
    assert is_error is False
    assert offline["campaign"]["data_origin"] == "refreshed-cache"


def test_119_refresh_false_never_touches_the_fetch(tmp_path, monkeypatch):
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)
    stub = _install_fetch(monkeypatch, URLError("never used"))

    body, is_error = _call(ONLINE, {"refresh": False})

    assert is_error is False
    assert stub.calls == 0
    assert body["refresh"]["status"] == "disabled"
    assert body["refresh"]["error"] is None
    assert body["refresh"]["persisted"] is False
    assert body["cancellation"]["hard_bound_seconds"] == 110


def test_120_successful_refresh_reports_shape_only_provenance(tmp_path, monkeypatch):
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)
    _install_fetch(monkeypatch, b"remote-package\nsecond-package\n")

    body, is_error = _call(ONLINE, {"refresh": True})

    assert is_error is False
    refresh = body["refresh"]
    assert refresh["verified"] == "shape-only"
    assert len(refresh["sha256"]) == 64
    int(refresh["sha256"], 16)
    assert refresh["retrieved_at"]
    assert refresh["package_count"] == 2
    assert refresh["source_url"] == SOURCE_URL


# -- network shape -------------------------------------------------------- #


class _RedirectHandler(BaseHTTPRequestHandler):
    hits = {"target": 0}

    def do_GET(self):
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "/target")
            self.end_headers()
            return
        type(self).hits["target"] += 1
        self.send_response(200)
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"a\nb")

    def log_message(self, *args):
        pass


def _serve(handler=_RedirectHandler):
    for _ in range(5):
        try:
            server = HTTPServer(("127.0.0.1", 0), handler)
        except OSError:
            time.sleep(0.2)
            continue
        thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server
    raise AssertionError("no loopback port")


def test_121_a_redirect_is_rejected_before_the_target_is_contacted(tmp_path, monkeypatch):
    _RedirectHandler.hits["target"] = 0
    server = _serve()
    port = server.server_address[1]
    try:
        url = "https://127.0.0.1:%d/redir" % port
        request = Request(url)
        request.full_url = request.full_url.replace("https://", "http://", 1)
        with pytest.raises(RedirectRejected):
            strict_urlopen(request, timeout=5)
        assert _RedirectHandler.hits["target"] == 0

        _state(tmp_path, monkeypatch)
        _root_patch(tmp_path, monkeypatch)
        _point_assets(tmp_path, monkeypatch, url=url)
        _http_rewrite(monkeypatch)

        body, is_error = _call(ONLINE, {"refresh": True})
    finally:
        server.shutdown()

    assert is_error is False
    assert body["refresh"]["status"] == "failed"
    assert body["refresh"]["error"] == "redirect_rejected"
    assert _RedirectHandler.hits["target"] == 0
    assert body["status"] == "partial"


def test_122_proxy_environment_does_not_steer_the_strict_fetch(tmp_path, monkeypatch):
    server = _serve()
    port = server.server_address[1]
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    try:
        request = Request("http://127.0.0.1:%d/target" % port)
        with strict_urlopen(request, timeout=5) as response:
            assert response.read(10) == b"a\nb"
        with pytest.raises(URLError):
            plain_urlopen("http://127.0.0.1:%d/target" % port, timeout=5)
    finally:
        server.shutdown()

    handlers = core.build_opener(
        core.ProxyHandler({}), core._RejectRedirects()
    ).handlers
    types = [type(handler).__name__ for handler in handlers]
    assert "ProxyHandler" not in types
    assert "HTTPRedirectHandler" not in types
    assert "_RejectRedirects" in types


# -- failure ladder ------------------------------------------------------- #


def _failure_arms():
    return [
        ("network_error", URLError("boom"), "network_error"),
        ("http_error", HTTPError(SOURCE_URL, 404, "not found", {}, None), "http_error"),
        # Over-cap is raised by the core read, outside the wrapper, so the label falls back while the
        # note keeps the core's fixed sentence.
        ("invalid_feed", b"x" * (MAX_CAMPAIGN_BYTES + 1),
         "remote campaign feed exceeds the bounded size limit"),
        ("unknown", AssertionError("weird opener"), "unknown"),
    ]


def test_123_every_fetch_failure_is_a_fixed_label_and_not_an_error(tmp_path, monkeypatch):
    for label, behaviour, suffix in _failure_arms():
        _state(tmp_path, monkeypatch)
        _root_patch(tmp_path, monkeypatch)
        _point_assets(tmp_path, monkeypatch)
        _install_fetch(monkeypatch, behaviour)

        body, is_error = _call(ONLINE, {"refresh": True})

        assert is_error is False, label
        assert body["status"] == "partial", label
        assert body["refresh"]["status"] == "failed", label
        assert body["refresh"]["error"] == label, label
        assert body["campaign"]["data_origin"] == "bundled", label
        assert [
            note for note in body["notes"] if note.startswith("Campaign refresh failed")
        ] == ["Campaign refresh failed; retained validated bundled data: %s" % (suffix,)]


def test_124_no_raw_exception_text_reaches_the_wire(tmp_path, monkeypatch):
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)
    _install_fetch(
        monkeypatch,
        URLError("<urlopen error token=ABC123 via proxy corp-proxy.internal:3128>"),
    )

    body, is_error = _call(ONLINE, {"refresh": True})

    assert is_error is False
    text = json.dumps(body["refresh"]) + "\n" + "\n".join(body["notes"])
    assert "[Errno" not in text
    assert "urlopen error" not in text
    assert "corp-proxy.internal" not in text
    assert "ABC123" not in text
    # The only URL left is the campaign's own source, echoed from the manifest.
    assert text.count("https://") == 1
    assert SOURCE_URL in text


# -- child environment and argv ------------------------------------------- #


def test_125_child_environment_is_an_allowlist(tmp_path, monkeypatch):
    for name, value in (
        ("http_proxy", "http://127.0.0.1:9"),
        ("PYTHONPATH", "/nowhere"),
        ("LD_PRELOAD", "/nowhere.so"),
        ("GIT_DIR", "/nowhere"),
        ("_JAVA_OPTIONS", "-Xmx1g"),
        ("XDG_STATE_HOME", str(tmp_path / "other-state")),
        ("XDG_DATA_HOME", "/nowhere/data"),
    ):
        monkeypatch.setenv(name, value)
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)

    seen = []

    def fake_run(argv, **kwargs):
        seen.append(kwargs.get("env"))
        return _Result()

    monkeypatch.setattr(online_tool.subprocess, "run", fake_run)
    _call(ONLINE, {"refresh": False, "include_arch_audit": False})

    assert seen
    for env in seen:
        for name in ("http_proxy", "PYTHONPATH", "LD_PRELOAD", "GIT_DIR", "_JAVA_OPTIONS",
                     "XDG_DATA_HOME"):
            assert name not in env, name
        assert "PATH" in env
        assert "HOME" in env
        if os.environ.get("XDG_CACHE_HOME"):
            assert env["XDG_CACHE_HOME"] == os.environ["XDG_CACHE_HOME"]
        else:
            assert "XDG_CACHE_HOME" not in env


def test_126_argv_is_explicit_and_env_is_always_passed(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _shim(bin_dir / "pacman", "#!/bin/sh\nexit 0\n")
    shim = _shim(
        bin_dir / "arch-audit",
        "#!/bin/sh\nprintf '[{\"packages\":[\"vim\"],\"issues\":[\"CVE-2026-1\"],"
        "\"severity\":\"High\",\"status\":\"Vulnerable\",\"name\":\"ASA-2026-1\",\"type\":\"remote\"}]'\n",
    )
    monkeypatch.setenv("PATH", "%s:%s" % (bin_dir, os.environ.get("PATH", "")))
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)

    seen = []

    def fake_run(argv, **kwargs):
        seen.append((list(argv), kwargs))
        assert "shell" not in kwargs
        assert "env" in kwargs
        if argv[0].endswith("arch-audit"):
            return _Result(
                '[{"packages":["vim"],"issues":["CVE-2026-1"],"severity":"High",'
                '"status":"Vulnerable","name":"ASA-2026-1","type":"remote"}]'
            )
        return _Result()

    monkeypatch.setattr(online_tool.subprocess, "run", fake_run)
    _call(ONLINE, {"refresh": False})

    commands = [argv for argv, _kwargs in seen]
    pacman = [argv for argv in commands if argv[0] == "pacman"]
    assert pacman and pacman[0][-1] == "-Q"
    arch = [argv for argv in commands if argv[0] == str(shim)]
    assert len(arch) == 1
    assert arch[0][:2] == [str(shim), "--json"]


def test_132_evidence_follows_the_flag_on_both_lists(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = _shim(
        bin_dir / "arch-audit",
        "#!/bin/sh\necho '[]'\n",
    )
    monkeypatch.setenv("PATH", "%s:%s" % (bin_dir, os.environ.get("PATH", "")))
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch, names=("vim",))

    def fake_run(argv, **kwargs):
        if argv[0] == str(shim):
            return _Result(
                '[{"packages":["vim"],"issues":["CVE-2026-1"],"severity":"High",'
                '"status":"Vulnerable","name":"ASA-2026-1","type":"remote"}]'
            )
        return _Result("vim 2.0-1\n")

    monkeypatch.setattr(online_tool.subprocess, "run", fake_run)

    stripped, is_error = _call(ONLINE, {"refresh": False})
    assert is_error is False
    assert stripped["arch_audit"]["findings"]
    for item in stripped["findings"]:
        assert "evidence" not in item
    for item in stripped["arch_audit"]["findings"]:
        assert "evidence" not in item

    kept, is_error = _call(ONLINE, {"refresh": False, "include_evidence": True})
    assert is_error is False
    assert kept["arch_audit"]["findings"][0]["evidence"]
    for item in kept["findings"]:
        assert "evidence" in item


# -- cancellation and the budget ------------------------------------------ #


def test_127_a_cancel_at_the_boundary_stops_before_arch_audit(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "arch-ran"
    _shim(bin_dir / "pacman", "#!/bin/sh\nsleep 3\n")
    _shim(bin_dir / "arch-audit", "#!/bin/sh\ntouch %s\necho '[]'\n" % (marker,))
    env = {"PATH": "%s:%s" % (bin_dir, os.environ.get("PATH", ""))}
    _state(tmp_path, monkeypatch)
    root = _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)

    with spawn(root, args=["--budget", "%s=30" % ONLINE], env=env) as client:
        client.call(ONLINE, {"refresh": False}, request_id=7)
        time.sleep(0.4)
        client.send({
            "jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 7},
        })
        error = client.read_error(30)

    assert error["code"] == "cancelled"
    assert error["detail"] == "cancelled before the arch-audit phase"
    assert not marker.exists()


def test_128_the_child_phase_respects_the_budget(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _shim(bin_dir / "pacman", "#!/bin/sh\nsleep 3\n")
    env = {"PATH": "%s:%s" % (bin_dir, os.environ.get("PATH", ""))}
    _state(tmp_path, monkeypatch)
    root = _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)

    with spawn(root, args=["--budget", "%s=1" % ONLINE], env=env) as client:
        client.call(ONLINE, {"refresh": False}, request_id=3)
        error = client.read_error(30)
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 4})
        assert client.read()["id"] == 4

    assert error["code"] == "timeout"


def test_128b_a_stalled_fetch_becomes_a_timeout_not_an_unknown_note(tmp_path, monkeypatch):
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)

    def slow(request, timeout):
        time.sleep(3)
        return FakeResponse(b"remote-package\n")

    monkeypatch.setattr(online_tool, "strict_urlopen", slow)

    loop = Loop(("/tmp",), budgets={ONLINE: 1})
    started = time.monotonic()
    loop.call(ONLINE, {"refresh": True})
    body = json.loads(loop.lines()[-1]["result"]["content"][0]["text"])

    assert loop.lines()[-1]["result"]["isError"] is True
    assert body["error"]["code"] == "timeout"
    assert time.monotonic() - started < 3
    loop.feed({"jsonrpc": "2.0", "method": "ping", "id": 5})
    assert loop.lines()[-1]["result"] == {}


def test_129_a_dead_network_still_returns_a_full_report(tmp_path, monkeypatch):
    _state(tmp_path, monkeypatch)
    _root_patch(tmp_path, monkeypatch)
    _point_assets(tmp_path, monkeypatch)
    _install_fetch(monkeypatch, URLError("no route to host"))

    body, is_error = _call(ONLINE, {"refresh": True})

    assert is_error is False
    assert body["refresh"]["status"] == "failed"
    assert body["refresh"]["error"] == "network_error"
    assert body["campaign"]["data_origin"] == "bundled"
    assert body["findings"] is not None
    assert body["advisory"] is True


# -- core-level contracts ------------------------------------------------- #


def test_130_persist_refresh_false_writes_nothing(tmp_path):
    manifest, packages = _write_campaign(tmp_path)
    campaign, _notes = core.load_campaign_intel(
        manifest_path=manifest, package_list_path=packages,
    )

    def stub(request, timeout):
        return FakeResponse(b"new-package\n")

    state = tmp_path / "state"
    refreshed = core.refresh_campaign_intel(
        campaign, state_root=state, urlopen=stub, persist_refresh=False,
    )
    assert refreshed.package_names == {"new-package"}
    assert refreshed.data_origin == "refreshed"
    assert not state.exists()

    persisted = core.refresh_campaign_intel(campaign, state_root=state, urlopen=stub)
    assert persisted.data_origin == "refreshed-cache"
    assert (state / PACKAGES).is_file()


def test_131_the_poll_hook_runs_at_both_boundaries(tmp_path, monkeypatch):
    manifest, packages = _write_campaign(tmp_path)
    order = []

    def runner(argv, **kwargs):
        order.append("process")
        return _Result()

    def fake_arch(**kwargs):
        order.append("arch")
        return core.ArchAuditResult(status="disabled")

    monkeypatch.setattr(core, "run_arch_audit", fake_arch)

    def poll():
        order.append("poll")

    report = core.build_security_audit(
        runner=runner,
        root=_root(tmp_path),
        home=tmp_path,
        manifest_path=manifest,
        package_list_path=packages,
        include_host_indicators=False,
        poll=poll,
    )
    assert report is not None
    assert order.count("poll") == 2
    assert order[0] == "poll"
    assert order.index("poll") < order.index("process")
    assert order.index("arch") > order.index("poll", 1)

    order.clear()

    def raise_on_second():
        order.append("poll")
        if order.count("poll") == 2:
            raise RuntimeError("stop")

    with pytest.raises(RuntimeError):
        core.build_security_audit(
            runner=runner,
            root=_root(tmp_path),
            home=tmp_path,
            manifest_path=manifest,
            package_list_path=packages,
            include_host_indicators=False,
            poll=raise_on_second,
        )
    assert "arch" not in order
