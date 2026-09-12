"""Explicit, bounded download of untrusted intelligence release assets.

Only the activation boundary authenticates these bytes. No project settings,
proxies, credentials, cookies, package tools or downloaded commands are used.
"""

import fcntl
import os
from pathlib import Path
import re
import ssl
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener,
)

from aurascan.core.intelligence import (
    IntelligenceError, MANIFEST_FILENAME, PAYLOAD_FILENAME, SIGNATURE_FILENAME,
)


PRODUCTION_FEED_BASE = ""
STAGING_ROOT = Path("/var/lib/aurascan-intelligence-staging")
ASSET_LIMITS = {
    MANIFEST_FILENAME: 64 * 1024,
    SIGNATURE_FILENAME: 64 * 1024,
    PAYLOAD_FILENAME: 2 * 1024 * 1024,
}
DOWNLOAD_SECONDS = 90
MAX_REDIRECTS = 3


def _feed_identity(base):
    if not isinstance(base, str) or len(base) > 512:
        raise IntelligenceError("intelligence feed configuration is invalid")
    parsed = urlsplit(base)
    if (parsed.scheme != "https" or parsed.netloc != "github.com"
            or parsed.query or parsed.fragment
            or not re.fullmatch(
                r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/latest/download", parsed.path)):
        raise IntelligenceError("intelligence feed is unconfigured or invalid")
    owner, repository = parsed.path.split("/")[1:3]
    if owner in {".", ".."} or repository in {".", ".."}:
        raise IntelligenceError("intelligence feed configuration is invalid")
    return "/" + owner + "/" + repository + "/releases/"


def assert_feed_configured():
    _feed_identity(PRODUCTION_FEED_BASE)


class _ReleaseRedirects(HTTPRedirectHandler):
    def __init__(self, repository_prefix, filename, deadline=None):
        self.repository_prefix = repository_prefix
        self.filename = filename
        self.count = 0
        self.deadline = time.monotonic() + DOWNLOAD_SECONDS if deadline is None else deadline

    def http_error_302(self, req, fp, code, msg, headers):
        # The stdlib handler drains fp.read() without a byte bound. Release
        # redirects have no useful body; close it before continuing instead.
        try:
            locations = (headers.get_all("Location") or [] if hasattr(headers, "get_all")
                         else [headers.get("Location", headers.get("location"))])
            if len(locations) != 1:
                raise IntelligenceError("intelligence download redirect refused")
            location = locations[0]
            if (not isinstance(location, str) or not location or len(location) > 4096
                    or not location.isascii()
                    or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in location)):
                raise IntelligenceError("intelligence download redirect refused")
            rewritten = self.redirect_request(req, fp, code, msg, headers,
                                              urljoin(req.full_url, location))
        finally:
            fp.close()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise IntelligenceError("intelligence download deadline exceeded")
        return self.parent.open(rewritten, timeout=min(10, remaining))

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        if (self.count > MAX_REDIRECTS or not isinstance(newurl, str)
                or len(newurl) > 4096 or time.monotonic() >= self.deadline):
            raise IntelligenceError("intelligence download redirect refused")
        parsed = urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.fragment
                or code not in {301, 302, 303, 307, 308}):
            raise IntelligenceError("intelligence download redirect refused")
        github_path = (
            parsed.netloc == "github.com" and not parsed.query
            and re.fullmatch(re.escape(self.repository_prefix) + r"download/[A-Za-z0-9_.-]+/"
                             + re.escape(self.filename), parsed.path)
        )
        asset_path = (
            parsed.netloc == "release-assets.githubusercontent.com"
            and re.fullmatch(r"/github-production-release-asset/[A-Za-z0-9_./-]+", parsed.path)
            and ".." not in parsed.path.split("/")
        )
        if not (github_path or asset_path):
            raise IntelligenceError("intelligence download redirect refused")
        # Rebuild a fixed GET instead of forwarding server or caller headers.
        return Request(newurl, headers={"User-Agent": "AuraScan-intelligence/1.0",
                                       "Accept-Encoding": "identity"}, method="GET")


def _download(base, name, limit, deadline, *, opener_factory=build_opener):
    prefix = _feed_identity(base)
    # Explicit system trust store prevents SSL_CERT_FILE/SSL_CERT_DIR overrides.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    defaults = ssl.get_default_verify_paths()
    context.load_verify_locations(cafile=defaults.openssl_cafile, capath=defaults.openssl_capath)
    opener = opener_factory(ProxyHandler({}), HTTPSHandler(context=context),
                            _ReleaseRedirects(prefix, name, deadline))
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise IntelligenceError("intelligence download deadline exceeded")
    request = Request(base + "/" + name,
                      headers={"User-Agent": "AuraScan-intelligence/1.0",
                               "Accept-Encoding": "identity"}, method="GET")
    try:
        with opener.open(request, timeout=min(10, remaining)) as response:
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise IntelligenceError("intelligence download response refused")
            declared = response.headers.get("Content-Length")
            if declared is not None and (not re.fullmatch(r"[0-9]{1,10}", declared)
                                         or int(declared) > limit):
                raise IntelligenceError("intelligence download size refused")
            data = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise IntelligenceError("intelligence download deadline exceeded")
                chunk = response.read(min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise IntelligenceError("intelligence download size refused")
            if not data or (declared is not None and len(data) != int(declared)):
                raise IntelligenceError("intelligence download was incomplete")
            return bytes(data)
    except (HTTPError, URLError, OSError, ValueError) as exc:
        # Never log redirected release URLs, response bodies or transport errors.
        raise IntelligenceError("intelligence download failed") from None


def _open_staging(directory, owner_uid, *, strict_parents=True):
    directory = Path(directory)
    if not directory.is_absolute() or ".." in directory.parts:
        raise IntelligenceError("intelligence staging path refused")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(directory.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            observed = os.fstat(fd)
            final = index == len(directory.parts) - 2
            expected = owner_uid if final else 0
            if (final or strict_parents) and (observed.st_uid != expected or observed.st_mode & 0o022):
                raise IntelligenceError("intelligence staging ownership refused")
        return fd
    except Exception:
        os.close(fd)
        raise


def fetch_bundle(*, base=None, staging=STAGING_ROOT, owner_uid=None, downloader=_download):
    """Fetch fixed assets as untrusted bytes; called only by the fetch service.

    Keyword injection exists for tests. The public CLI has no feed/path override.
    """
    base = PRODUCTION_FEED_BASE if base is None else base
    _feed_identity(base)
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    directory_fd = _open_staging(staging, owner_uid, strict_parents=Path(staging) == STAGING_ROOT)
    lock_fd = -1
    try:
        lock_fd = os.open(".fetch.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                          0o600, dir_fd=directory_fd)
        lock_stat = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != owner_uid
                or lock_stat.st_nlink != 1 or lock_stat.st_mode & 0o077):
            raise IntelligenceError("intelligence staging lock refused")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise IntelligenceError("intelligence download is already running") from None
        deadline = time.monotonic() + DOWNLOAD_SECONDS
        captured = {name: downloader(base, name, limit, deadline)
                    for name, limit in ASSET_LIMITS.items()}
        # Manifest is last. Activation still verifies the entire captured set;
        # interrupted or concurrently replaced staging can never establish trust.
        for name in (PAYLOAD_FILENAME, SIGNATURE_FILENAME, MANIFEST_FILENAME):
            temporary = "." + name + ".download"
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            try:
                data = captured[name]
                offset = 0
                while offset < len(data):
                    written = os.write(fd, data[offset:])
                    if written <= 0:
                        raise IntelligenceError("intelligence staging write failed")
                    offset += written
                os.fsync(fd)
                os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        os.fsync(directory_fd)
    except OSError:
        raise IntelligenceError("intelligence staging operation failed") from None
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(directory_fd)
