"""Explicit, bounded developer-only source capture; never execute source content.

Network adapters select files at asserted exact revisions, not complete trees.
Local revisions are caller assertions: this module never invokes Git to prove
them. Captured licenses and registry availability convey no corpus permission.
"""

import datetime
from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
from http.client import HTTPException
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from xml.etree import ElementTree


MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MAX_CAPTURES = 8
MAX_FILES = 8
MAX_REQUESTS = 40
DEADLINE_SECONDS = 45.0
NETWORK_HOSTS = frozenset({"gitlab.archlinux.org", "aur.archlinux.org"})
REFERENCE_HOSTS = NETWORK_HOSTS | frozenset({
    "github.com", "osv.dev", "nvd.nist.gov", "www.cve.org", "cve.org",
    "security.archlinux.org", "archlinux.org", "www.aikido.dev",
})
PACKAGE = re.compile(r"[a-z0-9][a-z0-9@._+\-]{0,127}\Z")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
LOCAL_NAME = re.compile(r"[A-Za-z0-9_.+\-]{1,128}\Z")


class SourceError(ValueError):
    """Only fixed internal codes are emitted; no source or transport prose."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass
class Capture:
    source_type: str
    source_uri: str
    package: Optional[str]
    package_version: Optional[str]
    revision: Optional[str]
    parent_revisions: List[str]
    retrieved_at: str
    files: Dict[str, bytes]
    coverage: str
    transport_sha256: List[str]


def _fail(code: str) -> None:
    raise SourceError(code)


def _package(value: Any) -> str:
    if not isinstance(value, str) or not PACKAGE.fullmatch(value):
        _fail("package_invalid")
    return value


def _revision(value: Any) -> str:
    if not isinstance(value, str) or not REVISION.fullmatch(value):
        _fail("revision_invalid")
    return value


def _revisions(values: Sequence[str], maximum: int = MAX_CAPTURES) -> List[str]:
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= maximum:
        _fail("revision_count")
    result = [_revision(value) for value in values]
    if len(result) != len(set(result)):
        _fail("revision_duplicate")
    return result


def _parents(values: Any, revision: str) -> List[str]:
    if not isinstance(values, (list, tuple)) or len(values) > 8:
        _fail("parents_invalid")
    result = [_revision(value) for value in values]
    if len(set(result)) != len(result) or revision in result:
        _fail("parents_invalid")
    return result


def _timestamp(now: Any = None) -> str:
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    if isinstance(now, datetime.datetime):
        if now.tzinfo is None or now.utcoffset() is None:
            _fail("timestamp_invalid")
        return now.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(now, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", now):
        try:
            datetime.datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            _fail("timestamp_invalid")
        return now
    _fail("timestamp_invalid")


def _uri(value: Any, hosts: Any = REFERENCE_HOSTS, query: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(
        ord(character) <= 32 or ord(character) == 127 for character in value
    ) or "\\" in value:
        _fail("source_uri_invalid")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or parsed.hostname not in hosts
                or parsed.username is not None or parsed.password is not None
                or parsed.port is not None or parsed.fragment or (parsed.query and not query)
                or parsed.netloc != parsed.hostname or not parsed.path.startswith("/")):
            _fail("source_uri_invalid")
    except ValueError:
        raise SourceError("source_uri_invalid") from None
    return value


def _json(payload: bytes) -> Any:
    if len(payload) > MAX_FILE_BYTES:
        _fail("source_size")
    # Bound nesting before the recursive standard JSON decoder is entered.
    depth, quoted, escaped = 0, False, False
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                _fail("json_depth")
        elif byte in (93, 125):
            depth -= 1

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail("json_duplicate_key")
            result[key] = value
        return result

    def integer(value):
        if len(value) > 20:
            _fail("json_number")
        return int(value)

    def reject(_value):
        _fail("json_number")

    def decimal(value):
        if len(value) > 64:
            _fail("json_number")
        result = float(value)
        if not math.isfinite(result):
            _fail("json_number")
        return result

    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=unique,
                          parse_int=integer, parse_float=decimal, parse_constant=reject)
    except SourceError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise SourceError("json_invalid") from None
    pending, nodes = [data], 0
    while pending:
        value = pending.pop()
        nodes += 1
        if nodes > 12000:
            _fail("json_nodes")
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            _fail("json_string")
    return data


def _metadata_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _text(payload: bytes) -> str:
    if len(payload) > MAX_FILE_BYTES:
        _fail("source_size")
    try:
        result = payload.decode("utf-8")
    except UnicodeError:
        raise SourceError("source_not_text") from None
    if "\x00" in result:
        _fail("source_not_text")
    if re.match(r"\s*(?:<!doctype\s+html|<html|<head|<body)", result, re.I):
        _fail("source_html")
    return result


def _version(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._+:~\-]{1,128}", value):
        _fail("version_invalid")
    return value


def _srcinfo(payload: bytes, package: str) -> str:
    fields = {}  # type: Dict[str, str]
    for line in _text(payload).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.fullmatch(r"([a-z][a-z0-9_]*)\s*=\s*(.+)", stripped)
        if not match:
            _fail("srcinfo_invalid")
        key, value = match.groups()
        if key in {"pkgbase", "pkgver", "pkgrel", "epoch"}:
            if key in fields:
                _fail("srcinfo_invalid")
            fields[key] = value
    if fields.get("pkgbase") != package:
        _fail("package_identity")
    if "pkgver" not in fields or "pkgrel" not in fields:
        _fail("srcinfo_invalid")
    epoch = fields.get("epoch")
    if epoch is not None and not re.fullmatch(r"[0-9]{1,10}", epoch):
        _fail("srcinfo_invalid")
    version = _version(fields["pkgver"]) + "-" + _version(fields["pkgrel"])
    return _version((epoch + ":" if epoch and int(epoch) else "") + version)


def _local_name(value: Any) -> str:
    if (not isinstance(value, str) or len(value) > 512 or value.startswith("/")
            or len(value.split("/")) > 8 or any(
                part in {".", ".."} or not LOCAL_NAME.fullmatch(part)
                for part in value.split("/"))):
        _fail("selected_path_invalid")
    return value


def _continued_shell_text(payload: bytes) -> str:
    text = _text(payload)
    result = []
    quote_state, comment, index = None, False, 0
    while index < len(text):
        character = text[index]
        if comment:
            result.append(character)
            if character == "\n":
                comment = False
        elif character == "\\" and quote_state != "'" and index + 1 < len(text):
            following = text[index + 1]
            if following != "\n":
                result.extend((character, following))
            index += 1
        elif character in {"'", '"'}:
            if quote_state is None:
                quote_state = character
            elif quote_state == character:
                quote_state = None
            result.append(character)
        else:
            if character == "#" and quote_state is None and (index == 0 or text[index - 1] in " \t\n;|&()"):
                comment = True
            result.append(character)
        index += 1
    return "".join(result)


def _install_hook(payload: bytes) -> Optional[str]:
    """Accept only a single literal assignment; never evaluate shell syntax."""
    found = []
    for line in _continued_shell_text(payload).splitlines():
        if line.lstrip().startswith("#"):
            continue
        if not re.search(r"(?<![A-Za-z0-9_])install\s*(?:\+?=|\[)", line):
            continue
        match = re.fullmatch(r"\s*install=(.*)", line)
        if not match or any(character in match.group(1) for character in "$`\\;\n"):
            _fail("install_hook_unsupported")
        try:
            tokens = shlex.split(match.group(1), comments=True, posix=True)
        except ValueError:
            raise SourceError("install_hook_unsupported") from None
        if len(tokens) != 1:
            _fail("install_hook_unsupported")
        found.append(_local_name(tokens[0]))
    if len(found) > 1:
        _fail("install_hook_unsupported")
    return found[0] if found else None


def _identity(info: Any) -> Tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class _LocalSnapshot:
    """Hold no-follow descriptors until the complete selected set is checked."""

    def __init__(self):
        self.descriptors = []  # type: List[int]
        self.links = []  # type: List[Tuple[int, str, int, int]]
        self.files = []  # type: List[Tuple[int, int, str, Tuple[int, ...]]]
        self.missing = []  # type: List[Tuple[int, str]]
        self.total = 0

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        try:
            if kind is None:
                self.verify()
        finally:
            for descriptor in reversed(self.descriptors):
                os.close(descriptor)

    def verify(self):
        try:
            for descriptor, parent, name, identity in self.files:
                if (_identity(os.fstat(descriptor)) != identity or
                        _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity):
                    _fail("source_changed")
            for parent, name, device, inode in self.links:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
                    _fail("source_changed")
            for parent, name in self.missing:
                try:
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _fail("source_changed")
        except OSError:
            raise SourceError("source_changed") from None

    def read(self, path: Path, optional: bool = False) -> Optional[bytes]:
        try:
            raw = os.fspath(path)
            if (not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 4096
                    or any(ord(char) < 32 or ord(char) == 127 for char in raw)):
                _fail("source_path_invalid")
            selected = Path(raw)
            if ".." in selected.parts:
                _fail("source_path_invalid")
            if not selected.is_absolute():
                selected = Path.cwd() / selected
            parts = selected.parts[1:]
            if not parts or len(parts) > 64:
                _fail("source_path_invalid")
            if not all(getattr(os, option, 0) for option in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
                _fail("no_follow_unavailable")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            parent = os.open("/", flags)
            self.descriptors.append(parent)
            for part in parts[:-1]:
                child = os.open(part, flags, dir_fd=parent)
                self.descriptors.append(child)
                info = os.fstat(child)
                self.links.append((parent, part, info.st_dev, info.st_ino))
                parent = child
            try:
                target = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                if optional:
                    self.missing.append((parent, parts[-1]))
                    return None
                raise
            self.descriptors.append(target)
            before = os.fstat(target)
            if not stat.S_ISREG(before.st_mode):
                _fail("source_not_regular")
            if before.st_size < 0 or before.st_size > MAX_FILE_BYTES:
                _fail("source_size")
            payload = bytearray()
            while len(payload) <= MAX_FILE_BYTES:
                chunk = os.read(target, min(16384, MAX_FILE_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > MAX_FILE_BYTES:
                _fail("source_size")
            self.total += len(payload)
            if self.total > MAX_TOTAL_BYTES:
                _fail("source_total_size")
            if len(payload) != before.st_size or _identity(before) != _identity(os.fstat(target)):
                _fail("source_changed")
            self.files.append((target, parent, parts[-1], _identity(before)))
            return bytes(payload)
        except SourceError:
            raise
        except (OSError, TypeError, ValueError, UnicodeError):
            raise SourceError("source_unsafe_or_unreadable") from None


def _local_files(root: Path, fixture: bool, selected_files: Sequence[str] = ()) -> Dict[str, bytes]:
    if not isinstance(selected_files, (list, tuple)) or len(selected_files) > MAX_FILES - 3:
        _fail("selected_file_count")
    extras = [_local_name(name) for name in selected_files]
    if len(extras) != len(set(extras)) or set(extras) & {"PKGBUILD", ".SRCINFO", "expected.json"}:
        _fail("selected_file_duplicate")
    result = {}  # type: Dict[str, bytes]
    with _LocalSnapshot() as snapshot:
        result["PKGBUILD"] = snapshot.read(root / "PKGBUILD")
        metadata_name = "expected.json" if fixture else ".SRCINFO"
        metadata = snapshot.read(root / metadata_name, optional=not fixture)
        if metadata is not None:
            result[metadata_name] = metadata
        hook = _install_hook(result["PKGBUILD"])
        for name in ([hook] if hook else []) + extras:
            if name in result:
                _fail("selected_file_duplicate")
            result[name] = snapshot.read(root / name)
    return result


def capture_fixture(root: Path, source_uri: str, revision: str, now: Any = None,
                    selected_files: Sequence[str] = ()) -> Capture:
    source_uri, revision, timestamp = _uri(source_uri), _revision(revision), _timestamp(now)
    files = _local_files(Path(root), True, selected_files)
    expected = _json(files["expected.json"])
    if not isinstance(expected, dict):
        _fail("fixture_metadata_invalid")
    package = _package(expected.get("package_name"))
    version = _version(expected.get("package_version"))
    return Capture("aurascan_fixture", source_uri, package, version, revision, [], timestamp,
                   files, "selected_files", [])


def capture_package(source_type: str, root: Path, source_uri: str, package: str,
                    revision: str, parent_revisions: Sequence[str] = (), now: Any = None) -> Capture:
    if not isinstance(source_type, str) or source_type not in {"arch_git", "aur_git"}:
        _fail("source_type_invalid")
    package, revision = _package(package), _revision(revision)
    source_uri, timestamp = _uri(source_uri), _timestamp(now)
    expected_uri = ("https://gitlab.archlinux.org/archlinux/packaging/packages/" + package
                    if source_type == "arch_git" else "https://aur.archlinux.org/" + package + ".git")
    if source_uri != expected_uri:
        _fail("package_identity")
    parents = _parents(parent_revisions, revision)
    files = _local_files(Path(root), False)
    version = _srcinfo(files[".SRCINFO"], package) if ".SRCINFO" in files else None
    return Capture(source_type, source_uri, package, version, revision, parents,
                   timestamp, files, "selected_files", [])


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        _fail("transport_redirect")


class _Transport:
    def __init__(self, network: bool, opener: Any):
        if network is not True:
            _fail("network_disabled")
        self.opener = opener if opener is not None else build_opener(ProxyHandler({}), _NoRedirect())
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.total = 0
        self.requests = 0
        self.hashes = []  # type: List[str]

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            _fail("transport_deadline")
        return remaining

    def get(self, uri: str, optional: bool = False, html: bool = False) -> Optional[bytes]:
        _uri(uri, NETWORK_HOSTS, query=True)
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            _fail("transport_request_limit")
        request = Request(uri, headers={"User-Agent": "AuraScan-Security-Data/1.0",
                                       "Accept-Encoding": "identity", "Accept": "*/*"}, method="GET")
        response = None
        try:
            response = self.opener.open(request, timeout=min(10.0, self.remaining()))
            self.remaining()
            if response.geturl() != uri:
                _fail("transport_redirect")
            status = response.status
            if status == 404 and optional:
                return None
            if status != 200:
                _http_error(status)
            encoding = response.headers.get("Content-Encoding", "identity")
            if encoding.lower() != "identity":
                _fail("transport_encoding")
            length = response.headers.get("Content-Length")
            if length is not None and (not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > MAX_FILE_BYTES):
                _fail("source_size")
            if not html and "text/html" in response.headers.get("Content-Type", "").lower():
                _fail("source_html")
            payload = bytearray()
            while len(payload) <= MAX_FILE_BYTES:
                remaining = self.remaining()
                # urllib's HTTPResponse has this socket; refresh its timeout so
                # slow response bodies cannot reset the combined deadline.
                sock = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
                if sock is not None:
                    sock.settimeout(min(10.0, remaining))
                read = getattr(response, "read1", response.read)
                chunk = read(min(16384, MAX_FILE_BYTES + 1 - len(payload)))
                self.remaining()
                if not chunk:
                    break
                payload.extend(chunk)
                self.total += len(chunk)
                if self.total > MAX_TOTAL_BYTES:
                    _fail("source_total_size")
            if len(payload) > MAX_FILE_BYTES:
                _fail("source_size")
            if length is not None and len(payload) != int(length):
                _fail("transport_incomplete")
            captured = bytes(payload)
            self.hashes.append(hashlib.sha256(captured).hexdigest())
            if not html:
                _text(captured)
            return captured
        except SourceError:
            raise
        except HTTPError as error:
            error.close()
            if error.code == 404 and optional:
                return None
            _http_error(error.code)
        except (OSError, URLError, HTTPException, ValueError, TypeError):
            raise SourceError("transport_failed") from None
        finally:
            if response is not None:
                response.close()


def _http_error(status: int) -> None:
    if status in {301, 302, 303, 307, 308}:
        _fail("transport_redirect")
    if status in {403, 404, 429}:
        _fail("transport_http_" + str(status))
    _fail("transport_http_error")


def _arch_base(package: str) -> str:
    project = quote("archlinux/packaging/packages/" + package, safe="")
    return "https://gitlab.archlinux.org/api/v4/projects/" + project + "/repository"


def resolve_arch_history(package: str, limit: int = 3, network: bool = False,
                         opener: Any = None) -> List[str]:
    package = _package(package)
    if type(limit) is not int or not 1 <= limit <= 3:
        _fail("history_limit")
    transport = _Transport(network, opener)
    records = _json(transport.get(_arch_base(package) + "/commits?" + urlencode({"per_page": limit})))
    if not isinstance(records, list) or not 1 <= len(records) <= limit:
        _fail("history_invalid")
    revisions = []
    for record in records:
        if not isinstance(record, dict):
            _fail("history_invalid")
        revision = _revision(record.get("id"))
        _parents(record.get("parent_ids"), revision)
        revisions.append(revision)
    return _revisions(revisions, 3)


def capture_arch(package: str, revisions: Sequence[str], network: bool = False,
                 opener: Any = None, now: Any = None) -> List[Capture]:
    package, revisions, timestamp = _package(package), _revisions(revisions), _timestamp(now)
    transport = _Transport(network, opener)
    result = []
    for revision in revisions:
        first_hash = len(transport.hashes)
        commit = _json(transport.get(_arch_base(package) + "/commits/" + revision))
        if not isinstance(commit, dict) or commit.get("id") != revision:
            _fail("revision_identity")
        parents = _parents(commit.get("parent_ids"), revision)
        def fetch(name, optional=False):
            uri = (_arch_base(package) + "/files/" + quote(name, safe="") + "/raw?"
                   + urlencode({"ref": revision}))
            return transport.get(uri, optional=optional)
        files, version = _network_files(fetch, package)
        result.append(Capture("arch_git", "https://gitlab.archlinux.org/archlinux/packaging/packages/" + package,
                              package, version, revision, parents, timestamp, files,
                              "selected_files", transport.hashes[first_hash:]))
    return result


def _network_files(fetch: Any, package: str) -> Tuple[Dict[str, bytes], Optional[str]]:
    files = {"PKGBUILD": fetch("PKGBUILD")}
    srcinfo = fetch(".SRCINFO", optional=True)
    if srcinfo is not None:
        files[".SRCINFO"] = srcinfo
    hook = _install_hook(files["PKGBUILD"])
    if hook:
        if hook in files:
            _fail("selected_file_duplicate")
        files[hook] = fetch(hook)
    version = _srcinfo(srcinfo, package) if srcinfo is not None else None
    return files, version


def capture_aur_metadata(package: str, network: bool = False, opener: Any = None,
                         now: Any = None) -> Capture:
    package, timestamp = _package(package), _timestamp(now)
    transport = _Transport(network, opener)
    data = _json(transport.get("https://aur.archlinux.org/rpc/v5/info/" + quote(package, safe="")))
    if (not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 5
            or data.get("type") != "multiinfo" or type(data.get("resultcount")) is not int
            or data["resultcount"] != 1 or not isinstance(data.get("results"), list)
            or len(data["results"]) != 1 or not isinstance(data["results"][0], dict)):
        _fail("aur_metadata_invalid")
    result = data["results"][0]
    if result.get("Name") != package:
        _fail("package_identity")
    base, version = _package(result.get("PackageBase")), _version(result.get("Version"))
    modified = result.get("LastModified")
    if type(modified) is not int or not 0 <= modified <= 253402300799:
        _fail("aur_metadata_invalid")
    metadata = {"name": package, "pkgbase": base, "version": version, "lastmodified": modified}
    return Capture("aur_metadata", "https://aur.archlinux.org/packages/" + package, base, version,
                   None, [], timestamp, {"metadata.json": _metadata_bytes(metadata)},
                   "metadata_only", transport.hashes[:])


class _CommitPage(HTMLParser):
    """Retain only commit/parent table cells, never author or message content."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []
        self.row = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag in {"td", "th"} and self.row is not None:
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in {"td", "th"} and self.cell is not None:
            self.row.append("".join(self.cell).strip())
            self.cell = None
        elif tag == "tr" and self.row is not None:
            if self.row and self.row[0] in {"commit", "parent"}:
                self.rows.append(self.row)
            self.row = None
            self.cell = None


def _aur_commit(payload: bytes, revision: str) -> List[str]:
    try:
        text = payload.decode("utf-8")
        parser = _CommitPage()
        parser.feed(text)
        parser.close()
    except (ValueError, UnicodeError, RecursionError):
        raise SourceError("aur_commit_invalid") from None
    commits, parents = [], []
    for row in parser.rows:
        if len(row) < 2:
            _fail("aur_commit_invalid")
        match = re.match(r"([0-9a-f]{64}|[0-9a-f]{40})(?:\s|$)", row[1])
        if not match:
            _fail("aur_commit_invalid")
        (commits if row[0] == "commit" else parents).append(match.group(1))
    if commits != [revision]:
        _fail("aur_commit_unavailable")
    return _parents(parents, revision)


def capture_aur(package: str, revisions: Sequence[str], network: bool = False,
                opener: Any = None, now: Any = None) -> List[Capture]:
    package, revisions, timestamp = _package(package), _revisions(revisions), _timestamp(now)
    transport = _Transport(network, opener)
    result = []
    for revision in revisions:
        first_hash = len(transport.hashes)
        query = urlencode({"h": package, "id": revision})
        page = transport.get("https://aur.archlinux.org/cgit/aur.git/commit/?" + query, html=True)
        parents = _aur_commit(page, revision)
        def fetch(name, optional=False):
            return transport.get("https://aur.archlinux.org/cgit/aur.git/plain/" + quote(name, safe="")
                                 + "?" + query, optional=optional)
        files, version = _network_files(fetch, package)
        result.append(Capture("aur_git", "https://aur.archlinux.org/" + package + ".git", package,
                              version, revision, parents, timestamp, files, "selected_files",
                              transport.hashes[first_hash:]))
    return result


def resolve_aur_history(package: str, limit: int = 3, network: bool = False,
                        opener: Any = None) -> List[str]:
    """Select only the newest bounded Atom entries; no whole-history claim."""
    package = _package(package)
    if type(limit) is not int or not 1 <= limit <= 3:
        _fail("history_limit")
    transport = _Transport(network, opener)
    payload = transport.get("https://aur.archlinux.org/cgit/aur.git/atom/?" + urlencode({"h": package}))
    text = _text(payload)
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        _fail("aur_history_invalid")
    try:
        root = ElementTree.fromstring(text)
    except (ElementTree.ParseError, ValueError, RecursionError):
        raise SourceError("aur_history_invalid") from None
    namespace = "{http://www.w3.org/2005/Atom}"
    if root.tag != namespace + "feed":
        _fail("aur_history_invalid")
    pending, count = [(root, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 6000 or depth > 16:
            _fail("aur_history_invalid")
        pending.extend((child, depth + 1) for child in node)
    entries = root.findall(namespace + "entry")
    if not entries or len(entries) > 100:
        _fail("aur_history_invalid")
    revisions = []
    for entry in entries[:limit]:
        identifiers = entry.findall(namespace + "id")
        if len(identifiers) != 1 or not isinstance(identifiers[0].text, str):
            _fail("aur_history_invalid")
        identifier = identifiers[0].text
        if identifier.startswith("urn:sha1:"):
            revision = identifier[len("urn:sha1:"):]
        else:
            _uri(identifier, {"aur.archlinux.org"}, query=True)
            parsed = urlsplit(identifier)
            query = parse_qs(parsed.query, keep_blank_values=True)
            if (parsed.path != "/cgit/aur.git/commit/" or set(query) - {"h", "id"}
                    or len(query.get("id", [])) != 1 or query.get("h", [package]) != [package]):
                _fail("aur_history_invalid")
            revision = query["id"][0]
        revisions.append(_revision(revision))
    return _revisions(revisions, 3)


def capture_advisory(identifier: str, source_uri: str, now: Any = None) -> Capture:
    if not isinstance(identifier, str) or not re.fullmatch(
        r"(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-[0-9]{4}-[0-9]{4,10}"
        r"|ASA-[0-9]{6}-[0-9]{1,6}|AVG-[0-9]{1,8}|(?:INCIDENT|ARCH-INCIDENT|AUR)-[A-Za-z0-9][A-Za-z0-9_.-]{1,120})",
        identifier,
    ):
        _fail("advisory_identifier")
    source_uri, timestamp = _uri(source_uri), _timestamp(now)
    host, path = urlsplit(source_uri).hostname, urlsplit(source_uri).path
    if host == "github.com" and not (path.startswith("/advisories/") or "/security/advisories/" in path):
        _fail("advisory_source")
    if host in NETWORK_HOSTS:
        _fail("advisory_source")
    if identifier.startswith("GHSA-"):
        if not ((host == "github.com" and re.fullmatch(
            r"/(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/security/)?advisories/" + re.escape(identifier), path
        )) or (host == "osv.dev" and path == "/vulnerability/" + identifier)):
            _fail("advisory_identity")
    elif identifier.startswith("CVE-"):
        allowed = {("nvd.nist.gov", "/vuln/detail/" + identifier),
                   ("osv.dev", "/vulnerability/" + identifier),
                   ("www.cve.org", "/CVERecord/" + identifier),
                   ("cve.org", "/CVERecord/" + identifier)}
        if (host, path) not in allowed:
            _fail("advisory_identity")
    elif identifier.startswith(("ASA-", "AVG-")):
        if host != "security.archlinux.org" or path != "/" + identifier:
            _fail("advisory_identity")
    return Capture("advisory", source_uri, None, None, None, [], timestamp,
                   {"reference.json": _metadata_bytes({"identifier": identifier, "source_uri": source_uri})},
                   "reference_only", [])
