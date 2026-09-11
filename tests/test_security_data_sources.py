"""Inert transport/source metadata tests; no live services or sample execution."""

import datetime
import hashlib
from http.client import BadStatusLine, IncompleteRead
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "security_data_sources", Path(__file__).resolve().parents[1] / "tools/security_data_sources.py"
)
sources = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = sources
_SPEC.loader.exec_module(sources)

REV = "a" * 40
PARENT = "b" * 40
NOW = "2026-09-10T12:00:00Z"
FIXTURE_URI = "https://github.com/crizzler/AuraScan/tree/" + REV + "/tests/fixtures/curated_packages/inert"
ARCH_URI = "https://gitlab.archlinux.org/archlinux/packaging/packages/inert"
SRCINFO = b"pkgbase = inert\n\tpkgver = 1.2\n\tpkgrel = 3\n\tpkgname = inert\n"
BUILD = b"pkgname=inert\npkgver=1.2\npkgrel=3\n# inert metadata only\n"


@pytest.fixture(autouse=True)
def no_live_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("source tests must not contact a live transport")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def encoded(value):
    return json.dumps(value).encode("utf-8")


class Response(io.BytesIO):
    def __init__(self, payload, uri=None, status=200, headers=None):
        super().__init__(payload)
        self.uri = uri
        self.status = status
        self.headers = headers or {}

    def geturl(self):
        return self.uri


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        assert 0 < timeout <= 10
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if isinstance(response, bytes):
            response = Response(response)
        if response.uri is None:
            response.uri = request.full_url
        return response


def local(tmp_path, fixture=False, hook=None):
    (tmp_path / "PKGBUILD").write_bytes(BUILD + (b"install=" + hook.encode() + b"\n" if hook else b""))
    if fixture:
        (tmp_path / "expected.json").write_bytes(encoded({
            "package_name": "inert", "package_version": "1.2", "expected_action": "not_executed",
        }))
    else:
        (tmp_path / ".SRCINFO").write_bytes(SRCINFO)
    return tmp_path


def package(root, **kwargs):
    return sources.capture_package("arch_git", root, ARCH_URI, "inert", REV, [PARENT], NOW, **kwargs)


def error(code, callback):
    with pytest.raises(sources.SourceError) as caught:
        callback()
    assert caught.value.code == code
    assert str(caught.value) == code
    return caught.value


def arch_opener(build=BUILD, srcinfo=SRCINFO, commit=None, after=()):
    return Opener([encoded(commit or {"id": REV, "parent_ids": [PARENT], "author_email": "secret@example.invalid"}),
                   build, srcinfo] + list(after))


def commit_page(revision=REV, parent=PARENT):
    return ("<html><table><tr><th>author</th><td>private@example.invalid</td></tr>"
            "<tr><th>commit</th><td><a>" + revision + "</a> (patch)</td></tr>"
            + ("<tr><th>parent</th><td><a>" + parent + "</a> (diff)</td></tr>" if parent else "")
            + "</table></html>").encode()


def rpc(**overrides):
    record = {"Name": "inert", "PackageBase": "inert", "Version": "1.2-3", "LastModified": 1789000000,
              "Maintainer": "private-name", "URL": "https://example.invalid/secret?token=private",
              "Description": "never retain me", "License": ["MIT"]}
    record["Popularity"] = 0.012345
    record.update(overrides)
    return {"version": 5, "type": "multiinfo", "resultcount": 1, "results": [record]}


def test_fixture_capture_is_selected_only_and_retains_inert_hook(tmp_path):
    root = local(tmp_path, fixture=True, hook=".inert.install")
    hook = b"# inert fixture command: never execute\necho FAKE_SECRET\n"
    (root / ".inert.install").write_bytes(hook)
    (root / "unselected-secret").write_bytes(b"private")
    result = sources.capture_fixture(root, FIXTURE_URI, REV, now=NOW)
    assert set(result.files) == {"PKGBUILD", "expected.json", ".inert.install"}
    assert result.files[".inert.install"] == hook
    assert (result.package, result.package_version, result.coverage) == ("inert", "1.2", "selected_files")
    assert (result.revision, result.retrieved_at, result.transport_sha256) == (REV, NOW, [])
    assert result.source_type == "aurascan_fixture"


def test_fixture_can_select_an_explicit_opaque_file_without_loading_it(tmp_path):
    root = local(tmp_path, fixture=True)
    (root / "inert.bin").write_bytes(b"\x00\xffinert")
    result = sources.capture_fixture(root, FIXTURE_URI, REV, NOW, selected_files=["inert.bin"])
    assert result.files["inert.bin"] == b"\x00\xffinert"


def test_package_version_comes_only_from_srcinfo_and_revision_is_asserted(tmp_path):
    root = local(tmp_path)
    (root / "PKGBUILD").write_bytes(b"pkgver=$(never_execute_this)\n")
    result = package(root)
    assert result.package_version == "1.2-3"
    assert result.parent_revisions == [PARENT]
    (root / ".SRCINFO").unlink()
    assert package(root).package_version is None


@pytest.mark.parametrize("declaration", ["../unsafe.install", "/unsafe.install", "$pkgname.install",
                                        "$(never_execute)", "a.install; echo ignored", "'unterminated"])
def test_unsafe_or_dynamic_hooks_fail_without_following_them(tmp_path, declaration):
    root = local(tmp_path)
    (root / "PKGBUILD").write_bytes(BUILD + ("install=" + declaration + "\n").encode())
    with pytest.raises(sources.SourceError):
        package(root)


def test_duplicate_or_indirect_hook_declaration_fails(tmp_path):
    root = local(tmp_path)
    for declaration in [b"install=a\ninstall=b\n", b"declare install=a\n", b"install+=a\n"]:
        (root / "PKGBUILD").write_bytes(BUILD + declaration)
        error("install_hook_unsupported", lambda: package(root))


def test_missing_declared_hook_is_not_ignored(tmp_path):
    error("source_unsafe_or_unreadable", lambda: package(local(tmp_path, hook="absent.install")))


@pytest.mark.parametrize("target", ["PKGBUILD", ".SRCINFO", ".inert.install"])
def test_selected_symlink_is_never_followed(tmp_path, target):
    root = local(tmp_path, hook=".inert.install")
    secret = root / "private"
    secret.write_bytes(b"DO_NOT_READ_FAKE_SECRET")
    selected = root / target
    if selected.exists():
        selected.unlink()
    selected.symlink_to(secret)
    error("source_unsafe_or_unreadable", lambda: package(root))


def test_symlinked_parent_and_dotdot_root_fail(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    local(root)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    error("source_unsafe_or_unreadable", lambda: package(alias))
    error("source_path_invalid", lambda: package(root / ".." / "root"))


def test_fifo_is_rejected_without_blocking(tmp_path):
    root = local(tmp_path)
    (root / "PKGBUILD").unlink()
    os.mkfifo(root / "PKGBUILD")
    error("source_not_regular", lambda: package(root))


def test_replacement_after_another_selected_file_read_is_detected(tmp_path, monkeypatch):
    root = local(tmp_path)
    original_read = sources.os.read
    changed = False
    def replacing_read(descriptor, count):
        nonlocal changed
        payload = original_read(descriptor, count)
        if payload == SRCINFO and not changed:
            changed = True
            replacement = root / "replacement"
            replacement.write_bytes(BUILD)
            replacement.replace(root / "PKGBUILD")
        return payload
    monkeypatch.setattr(sources.os, "read", replacing_read)
    error("source_changed", lambda: package(root))


def test_short_read_cannot_claim_a_complete_snapshot(tmp_path, monkeypatch):
    root = local(tmp_path)
    monkeypatch.setattr(sources.os, "read", lambda descriptor, count: b"")
    error("source_changed", lambda: package(root))


def test_new_optional_metadata_before_snapshot_commit_invalidates_absence(tmp_path, monkeypatch):
    root = local(tmp_path, hook="inert.install")
    (root / ".SRCINFO").unlink()
    (root / "inert.install").write_bytes(b"# inert hook\n")
    original_read = sources.os.read
    def appearing_read(descriptor, count):
        payload = original_read(descriptor, count)
        if payload == b"# inert hook\n":
            (root / ".SRCINFO").write_bytes(SRCINFO)
        return payload
    monkeypatch.setattr(sources.os, "read", appearing_read)
    error("source_changed", lambda: package(root))


@pytest.mark.parametrize("payload,code", [
    (b'{"package_name":"inert","package_name":"other"}', "json_duplicate_key"),
    (b'{"package_name":NaN}', "json_number"),
    (b'{"package_name":1e999}', "json_number"),
    (b'[' * 17 + b']' * 17, "json_depth"),
    (b'{"package_name":"\\ud800"}', "json_string"),
    (b'not json FAKE_SECRET', "json_invalid"),
])
def test_fixture_metadata_is_strict_and_errors_are_redacted(tmp_path, payload, code, capsys):
    root = local(tmp_path, fixture=True)
    (root / "expected.json").write_bytes(payload)
    caught = error(code, lambda: sources.capture_fixture(root, FIXTURE_URI, REV, NOW))
    assert "FAKE_SECRET" not in repr(caught)
    assert capsys.readouterr() == ("", "")


def test_local_file_and_combined_size_limits(tmp_path, monkeypatch):
    root = local(tmp_path)
    monkeypatch.setattr(sources, "MAX_FILE_BYTES", len(BUILD) - 1)
    error("source_size", lambda: package(root))
    monkeypatch.setattr(sources, "MAX_FILE_BYTES", 256 * 1024)
    monkeypatch.setattr(sources, "MAX_TOTAL_BYTES", len(BUILD) + len(SRCINFO) - 1)
    error("source_total_size", lambda: package(root))


@pytest.mark.parametrize("invoke", [
    lambda: sources.capture_arch("inert", [REV]),
    lambda: sources.resolve_arch_history("inert"),
    lambda: sources.capture_aur("inert", [REV]),
    lambda: sources.capture_aur_metadata("inert"),
    lambda: sources.resolve_aur_history("inert"),
])
def test_network_always_requires_explicit_true(invoke):
    error("network_disabled", invoke)


def test_arch_snapshot_uses_exact_revision_and_discards_commit_author_metadata():
    opener = arch_opener(build=BUILD + b"install=.inert.install\n", after=[b"# inert hook\n"])
    result = sources.capture_arch("inert", [REV], True, opener, NOW)[0]
    assert result.package_version == "1.2-3"
    assert result.parent_revisions == [PARENT]
    assert set(result.files) == {"PKGBUILD", ".SRCINFO", ".inert.install"}
    assert len(result.transport_sha256) == 4
    assert "secret@example.invalid" not in repr(result)
    assert result.source_uri == ARCH_URI
    for request, timeout in opener.requests[1:]:
        assert parse_qs(urlsplit(request.full_url).query) == {"ref": [REV]}
        assert request.get_header("Accept-encoding") == "identity"
        assert not request.has_header("Authorization")


def test_arch_absent_srcinfo_is_unknown_version_without_fabrication():
    opener = arch_opener(srcinfo=Response(b"", status=404))
    result = sources.capture_arch("inert", [REV], True, opener, NOW)[0]
    assert set(result.files) == {"PKGBUILD"}
    assert result.package_version is None
    assert len(result.transport_sha256) == 2


def test_arch_history_selects_bounded_exact_ids_without_retaining_prose():
    records = [{"id": REV, "parent_ids": [PARENT], "message": "private"},
               {"id": PARENT, "parent_ids": []}]
    opener = Opener([encoded(records)])
    assert sources.resolve_arch_history("inert", 2, True, opener) == [REV, PARENT]
    assert parse_qs(urlsplit(opener.requests[0][0].full_url).query) == {"per_page": ["2"]}
    error("history_limit", lambda: sources.resolve_arch_history("inert", 4, True, opener))


@pytest.mark.parametrize("commit,code", [
    ({"id": PARENT, "parent_ids": []}, "revision_identity"),
    ({"id": REV, "parent_ids": [REV]}, "parents_invalid"),
    ({"id": REV, "parent_ids": ["main"]}, "revision_invalid"),
])
def test_arch_commit_identity_and_parents_are_validated(commit, code):
    error(code, lambda: sources.capture_arch("inert", [REV], True, arch_opener(commit=commit), NOW))


@pytest.mark.parametrize("payload,code", [
    (SRCINFO.replace(b"pkgbase = inert", b"pkgbase = different"), "package_identity"),
    (SRCINFO + b"pkgver = 9\n", "srcinfo_invalid"),
    (SRCINFO.replace(b"pkgver = 1.2", b"pkgver = $(fake)"), "version_invalid"),
    (b"<!doctype html><html>challenge</html>", "source_html"),
])
def test_srcinfo_does_not_accept_wrong_identity_shell_or_html(payload, code):
    error(code, lambda: sources.capture_arch("inert", [REV], True, arch_opener(srcinfo=payload), NOW))


def test_aur_rpc_retains_only_four_fields_and_raw_response_digest():
    payload = encoded(rpc())
    result = sources.capture_aur_metadata("inert", True, Opener([payload]), NOW)
    assert json.loads(result.files["metadata.json"]) == {
        "name": "inert", "pkgbase": "inert", "version": "1.2-3", "lastmodified": 1789000000,
    }
    assert result.transport_sha256 == [hashlib.sha256(payload).hexdigest()]
    assert result.coverage == "metadata_only"
    assert result.source_type == "aur_metadata"
    assert result.revision is None
    assert not any(value in repr(result) for value in ["private-name", "token=private", "MIT"])


def test_aur_split_package_metadata_uses_repository_base_identity():
    captures = []
    for name in ["example-cli", "example-library"]:
        payload = encoded(rpc(Name=name, PackageBase="example"))
        capture = sources.capture_aur_metadata(name, True, Opener([payload]), NOW)
        captures.append(capture)
        assert json.loads(capture.files["metadata.json"])["name"] == name
        assert json.loads(capture.files["metadata.json"])["pkgbase"] == "example"
        assert capture.source_uri == "https://aur.archlinux.org/packages/" + name
    base_srcinfo = SRCINFO.replace(b"inert", b"example")
    repository = sources.capture_aur("example", [REV], True,
                                     Opener([commit_page(), BUILD, base_srcinfo]), NOW)[0]
    assert captures[0].package == captures[1].package == repository.package == "example"


@pytest.mark.parametrize("data,code", [
    (rpc(Name="other"), "package_identity"),
    (rpc(LastModified=True), "aur_metadata_invalid"),
    (rpc(LastModified=-1), "aur_metadata_invalid"),
    (rpc(PackageBase="../private"), "package_invalid"),
    ({"version": 5, "type": "multiinfo", "resultcount": 0, "results": []}, "aur_metadata_invalid"),
    ({**rpc(), "version": "5"}, "aur_metadata_invalid"),
])
def test_malformed_or_wrong_aur_rpc_metadata_fails(data, code):
    error(code, lambda: sources.capture_aur_metadata("inert", True, Opener([encoded(data)]), NOW))


def test_aur_capture_binds_cgit_commit_and_parents_and_selected_files():
    opener = Opener([commit_page(), BUILD, SRCINFO])
    result = sources.capture_aur("inert", [REV], True, opener, NOW)[0]
    assert result.parent_revisions == [PARENT]
    assert result.package_version == "1.2-3"
    assert result.source_uri == "https://aur.archlinux.org/inert.git"
    assert "private@example.invalid" not in repr(result)
    for request, timeout in opener.requests:
        assert parse_qs(urlsplit(request.full_url).query) == {"h": ["inert"], "id": [REV]}


@pytest.mark.parametrize("payload", [commit_page(PARENT), b"<html>Anubis: execute challenge</html>",
                                     b"<html>private transport failure</html>"])
def test_aur_identity_or_challenge_failure_does_not_fabricate_a_capture(payload):
    opener = Opener([payload])
    error("aur_commit_unavailable", lambda: sources.capture_aur("inert", [REV], True, opener, NOW))
    assert len(opener.requests) == 1


@pytest.mark.parametrize("response,code", [
    (Response(b"", uri="https://example.invalid/redirect"), "transport_redirect"),
    (Response(b"", status=302), "transport_redirect"),
    (Response(b"", status=403), "transport_http_403"),
    (Response(b"", status=429), "transport_http_429"),
    (Response(b"private", headers={"Content-Type": "text/html"}), "source_html"),
    (Response(b"{}", headers={"Content-Encoding": "gzip"}), "transport_encoding"),
    (Response(b"{}", headers={"Content-Length": "3"}), "transport_incomplete"),
    (Response(b"{}", headers={"Content-Length": "9999999999"}), "source_size"),
    (URLError("FAKE_PRIVATE_TRANSPORT_ERROR"), "transport_failed"),
])
def test_transport_refuses_redirects_challenges_and_incomplete_bodies(response, code, capsys):
    error(code, lambda: sources.capture_aur_metadata("inert", True, Opener([response]), NOW))
    assert capsys.readouterr() == ("", "")


def test_http_error_is_closed_and_redacted():
    body = io.BytesIO(b"FAKE_PRIVATE_TRANSPORT_ERROR")
    response = HTTPError("https://aur.archlinux.org/", 403, "FAKE_SECRET", {}, body)
    error("transport_http_403", lambda: sources.capture_aur_metadata("inert", True, Opener([response]), NOW))
    assert body.closed


@pytest.mark.parametrize("exception", [IncompleteRead(b"FAKE_SECRET_PARTIAL_BODY", 42),
                                       BadStatusLine("FAKE_SECRET_STATUS_LINE")])
def test_http_protocol_exceptions_have_fixed_redacted_errors(exception, capsys):
    error("transport_failed", lambda: sources.capture_aur_metadata("inert", True, Opener([exception]), NOW))
    assert capsys.readouterr() == ("", "")


def test_default_opener_disables_environment_proxies_and_redirects(monkeypatch):
    captured = []
    def factory(*handlers):
        captured.extend(handlers)
        return Opener([encoded(rpc())])
    monkeypatch.setattr(sources, "build_opener", factory)
    monkeypatch.setenv("HTTPS_PROXY", "https://example.invalid/never-contact")
    sources.capture_aur_metadata("inert", True, now=NOW)
    assert captured[0].proxies == {}
    error("transport_redirect", lambda: captured[1].redirect_request(None, None, 302, "private", {}, "https://example.invalid/"))


@pytest.mark.parametrize("uri", ["http://aur.archlinux.org/x", "https://127.0.0.1/x", "https://localhost/x",
                                  "https://aur.archlinux.org.evil.invalid/x", "https://private@aur.archlinux.org/x",
                                  "https://aur.archlinux.org:443/x", "https://aur.archlinux.org/x#private"])
def test_transport_rejects_unapproved_authorities_before_open(uri):
    opener = Opener([])
    transport = sources._Transport(True, opener)
    error("source_uri_invalid", lambda: transport.get(uri))
    assert not opener.requests


def test_network_limits_count_actual_body_bytes_and_whole_batch(monkeypatch):
    monkeypatch.setattr(sources, "MAX_FILE_BYTES", 100)
    error("source_size", lambda: sources.capture_aur_metadata("inert", True, Opener([b"x" * 101]), NOW))
    monkeypatch.setattr(sources, "MAX_FILE_BYTES", 256 * 1024)
    monkeypatch.setattr(sources, "MAX_TOTAL_BYTES", len(BUILD))
    error("source_total_size", lambda: sources.capture_arch("inert", [REV], True, arch_opener(), NOW))


def test_network_deadline_and_capture_count_fail_closed(monkeypatch):
    clock = iter([0.0, 46.0])
    monkeypatch.setattr(sources.time, "monotonic", lambda: next(clock))
    opener = Opener([])
    error("transport_deadline", lambda: sources.capture_arch("inert", [REV], True, opener, NOW))
    assert not opener.requests
    error("revision_count", lambda: sources.capture_arch("inert", [REV] * 9, True, opener, NOW))
    error("revision_duplicate", lambda: sources.capture_arch("inert", [REV, REV], True, opener, NOW))


def test_advisory_is_reference_only_and_does_not_fetch_or_assert_a_verdict():
    uri = "https://github.com/advisories/GHSA-2345-6789-cfgh"
    result = sources.capture_advisory("GHSA-2345-6789-cfgh", uri, NOW)
    assert result.coverage == "reference_only"
    assert result.transport_sha256 == []
    assert json.loads(result.files["reference.json"]) == {"identifier": "GHSA-2345-6789-cfgh", "source_uri": uri}
    assert result.package is None and result.revision is None


@pytest.mark.parametrize("uri", ["https://github.com/advisories/GHSA-2345-6789-cfgh?token=private",
                                  "file:///private", "https://example.invalid/advisory",
                                  "https://github.com/private/repository", "https://aur.archlinux.org/packages/inert"])
def test_advisory_reference_refuses_unsafe_or_nonadvisory_sources(uri):
    with pytest.raises(sources.SourceError):
        sources.capture_advisory("GHSA-2345-6789-cfgh", uri, NOW)


def test_timestamp_normalizes_aware_time_and_rejects_ambiguous_time():
    now = datetime.datetime(2026, 9, 10, 20, tzinfo=datetime.timezone(datetime.timedelta(hours=8)))
    result = sources.capture_advisory("CVE-2026-12345", "https://nvd.nist.gov/vuln/detail/CVE-2026-12345", now)
    assert result.retrieved_at == NOW
    error("timestamp_invalid", lambda: sources.capture_advisory(
        "CVE-2026-12345", result.source_uri, datetime.datetime(2026, 9, 10)))


def test_wrong_local_package_uri_fails_before_reading(tmp_path):
    error("package_identity", lambda: sources.capture_package(
        "arch_git", tmp_path, ARCH_URI + "-other", "inert", REV, now=NOW))


@pytest.mark.parametrize("value", [None, [], {}, 1])
def test_invalid_source_type_has_a_fixed_error(tmp_path, value):
    error("source_type_invalid", lambda: sources.capture_package(
        value, tmp_path, ARCH_URI, "inert", REV, now=NOW))


def test_advisory_identifier_must_match_the_referenced_record():
    error("advisory_identity", lambda: sources.capture_advisory(
        "GHSA-2345-6789-cfgh", "https://github.com/advisories/GHSA-cfgh-2345-6789", NOW))
    error("advisory_identity", lambda: sources.capture_advisory(
        "CVE-2026-12345", "https://nvd.nist.gov/vuln/detail/CVE-2026-54321", NOW))
    assert sources.capture_advisory("ASA-202609-1", "https://security.archlinux.org/ASA-202609-1", NOW).coverage == "reference_only"
    assert sources.capture_advisory("AVG-1234", "https://security.archlinux.org/AVG-1234", NOW).coverage == "reference_only"


@pytest.mark.parametrize("declaration", [b"install\\\n=hidden.install\n", b"in\\\nstall=hidden.install\n",
                                         b"# comment \\\ninstall=hidden.install\n"])
def test_continued_hook_declarations_are_not_silently_omitted(tmp_path, declaration):
    root = local(tmp_path)
    (root / "PKGBUILD").write_bytes(BUILD + declaration)
    (root / "hidden.install").write_bytes(b"# inert\n")
    assert package(root).files["hidden.install"] == b"# inert\n"


def atom(identifiers):
    return ('<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">'
            + ''.join('<entry><id>' + identifier.replace('&', '&amp;')
                      + '</id><author><email>private@example.invalid</email></author></entry>'
                      for identifier in identifiers) + '</feed>').encode()


def test_aur_history_selects_exact_bounded_ids_without_retaining_author_data():
    payload = atom(["https://aur.archlinux.org/cgit/aur.git/commit/?h=inert&id=" + REV, "urn:sha1:" + PARENT])
    opener = Opener([payload])
    assert sources.resolve_aur_history("inert", 2, True, opener) == [REV, PARENT]
    assert parse_qs(urlsplit(opener.requests[0][0].full_url).query) == {"h": ["inert"]}


@pytest.mark.parametrize("payload,code", [
    (b'<!DOCTYPE feed [<!ENTITY external SYSTEM "file:///private">]><feed/>', "aur_history_invalid"),
    (b'<html>challenge</html>', "source_html"),
    (atom(["https://aur.archlinux.org/cgit/aur.git/commit/?h=other&id=" + REV]), "aur_history_invalid"),
    (atom(["urn:sha1:main"]), "revision_invalid"),
    (atom(["urn:sha1:" + REV, "urn:sha1:" + REV]), "revision_duplicate"),
    (b'<feed xmlns="http://www.w3.org/2005/Atom"></feed>', "aur_history_invalid"),
])
def test_aur_history_rejects_entities_wrong_identity_and_incomplete_data(payload, code):
    error(code, lambda: sources.resolve_aur_history("inert", 2, True, Opener([payload])))
