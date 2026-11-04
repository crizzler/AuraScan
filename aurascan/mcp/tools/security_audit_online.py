"""``security_audit_online``: the host audit plus one bounded, strict HTTPS campaign refresh.

``readOnlyHint: false`` is honest on three facts: the campaign feed is fetched over the network, ``pacman
-Q`` and ``arch-audit`` are executed, and the report can differ between two calls. ``destructiveHint:
false`` is honest because no AuraScan state is written: the refresh lives in the returned report only.
``arch-audit`` may keep its own cache under ``$XDG_CACHE_HOME``, which is the child's, not AuraScan's.

``shutil.which("arch-audit")`` still resolves on this server's own ``PATH``, not on the filtered child
environment: an operator who chooses the server environment chooses which binary the report names in
``arch_audit.command``. The filter bounds what the child sees, not which file is found.
"""

import os
import subprocess
from pathlib import Path
from urllib.error import HTTPError, URLError

from aurascan.core.security_audit import (
    RedirectRejected, build_security_audit, strict_urlopen,
)

from .. import results
from ..errors import TimeoutExpired, ToolError

_ROOT = Path("/")

DEFAULT_MAX_FINDINGS = 100

_CHILD_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "LANGUAGE", "TZ", "XDG_CACHE_HOME")

_REFRESH_DISABLED = "disabled"
_REFRESH_FAILED = "failed"
_REFRESH_OK = "refreshed"

CANCELLED_BEFORE = "cancelled before the audit started"
CANCELLED_REFRESH = "cancelled before the arch-audit phase"
CANCELLED_AFTER = "cancelled after the audit completed"

CAPABILITIES = {
    "process": (
        "one filtered-env `pacman -Q` (30 s) and, unless disabled, `arch-audit --json` (45 s); "
        "explicit argv"
    ),
    "fs_read": (
        "stats or reads the reported artifact paths under /etc, /usr/lib, /usr/bin and "
        "/usr/local/bin, /root/pamkeys, /var/log/pacman.log{,.1}, /sys/fs/bpf, the AUR helper "
        "cache and the campaign cache directory"
    ),
    "network": (
        "one HTTPS GET to the packaged manifest source_url, 20 s, 2 MiB cap; 3xx rejected before "
        "the redirect target is contacted; no proxy inheritance. `refresh: false` suppresses only "
        "AuraScan's own fetch - `arch-audit` may still reach its own feed"
    ),
    "state_writes": (
        "no AuraScan writes at all; `arch-audit` may maintain its own cache under "
        "`$XDG_CACHE_HOME`"
    ),
    "offline": False,
}


class _FetchFailure(ValueError):
    """A fetch failure reduced to one fixed label, so no exception text reaches the wire."""

    def __init__(self, label):
        ValueError.__init__(self, label)
        self.label = label


class _Fetch(object):
    """urlopen-shaped callable: fixed failure labels, redirect rejection mapped, no raw text.

    The budget alarm (``errors.TimeoutExpired``, not an ``OSError``) is re-raised untouched and
    *before* the catch-all, so the protocol's 110 s bound produces a ``timeout`` envelope instead of
    a report with an ``unknown`` note.
    """

    def __init__(self):
        self.label = None

    def __call__(self, request, timeout):
        try:
            return strict_urlopen(request, timeout=timeout)
        except TimeoutExpired:
            raise
        except RedirectRejected:
            self.label = "redirect_rejected"
            raise _FetchFailure("redirect_rejected")
        except HTTPError:
            self.label = "http_error"
            raise _FetchFailure("http_error")
        except URLError:
            self.label = "network_error"
            raise _FetchFailure("network_error")
        except UnicodeError:
            self.label = "invalid_feed"
            raise _FetchFailure("invalid_feed")
        except ValueError:
            self.label = "invalid_feed"
            raise _FetchFailure("invalid_feed")
        except OSError:
            self.label = "network_error"
            raise _FetchFailure("network_error")
        except Exception:
            self.label = "unknown"
            raise _FetchFailure("unknown")


def _child_env():
    """Allowlist, not denylist: proxy variables and ``PYTHON*``/``LD_*``/``GIT_*`` never reach a child."""
    env = {"PATH": os.environ.get("PATH") or "/usr/bin:/bin"}
    for key in _CHILD_ENV_KEYS:
        if key != "PATH" and os.environ.get(key):
            env[key] = os.environ[key]
    return env


def _runner(argv, **kwargs):
    """Injected runner: a real ``subprocess.run`` call site (process owner) with a fixed env."""
    kwargs["env"] = _child_env()
    return subprocess.run(argv, **kwargs)


def _refresh_block(refresh, report, fetch):
    """Derive ``refresh`` from the campaign the core handed back, in the documented order."""
    campaign = report.campaign
    block = {
        "requested": bool(refresh),
        "status": _REFRESH_DISABLED,
        "persisted": False,
        "error": None,
        "verified": "shape-only",
        "source_url": campaign.source_url if campaign is not None else None,
        "sha256": campaign.sha256 if campaign is not None else None,
        "retrieved_at": campaign.retrieved_at if campaign is not None else None,
        "package_count": len(campaign.package_names) if campaign is not None else 0,
    }
    if not refresh:
        return block
    if campaign is None:
        block["status"] = _REFRESH_FAILED
        block["error"] = "campaign_unavailable"
        return block
    if campaign.data_origin == "refreshed":
        block["status"] = _REFRESH_OK
        return block
    block["status"] = _REFRESH_FAILED
    block["error"] = fetch.label or "invalid_feed"
    return block


def handle(ctx, arguments):
    max_findings = arguments.get("max_findings", DEFAULT_MAX_FINDINGS)
    include_evidence = bool(arguments.get("include_evidence", False))
    refresh = bool(arguments.get("refresh", True))
    include_arch_audit = bool(arguments.get("include_arch_audit", True))
    if ctx.cancelled():
        raise ToolError("cancelled", CANCELLED_BEFORE)

    fetch = _Fetch()

    def poll():
        if ctx.cancelled():
            raise ToolError("cancelled", CANCELLED_REFRESH)

    try:
        report = build_security_audit(
            offline=False,
            refresh=refresh,
            persist_refresh=False,
            state_root=None,
            home=Path.home(),
            root=_ROOT,
            include_host_indicators=True,
            include_arch_audit=include_arch_audit,
            runner=_runner,
            urlopen=fetch,
            poll=poll,
        )
    except (OSError, subprocess.SubprocessError):
        raise ToolError("internal", "host audit failed")

    if ctx.cancelled():
        raise ToolError("cancelled", CANCELLED_AFTER)

    payload = report.to_dict()
    kept, truncated = results.project_findings(payload["findings"], max_findings)
    if not include_evidence:
        for item in kept:
            item.pop("evidence", None)
    payload["findings"] = kept
    payload["findings_truncated"] = truncated
    if not include_evidence:
        # Unlike the offline tool these are reachable: the arch audit really runs here.
        for item in payload["arch_audit"]["findings"]:
            item.pop("evidence", None)

    payload["refresh"] = _refresh_block(refresh, report, fetch)
    if payload["refresh"]["status"] == _REFRESH_FAILED and payload["status"] == "ok":
        payload["status"] = "partial"
    payload["advisory"] = True
    payload["cancellation"] = {
        "advisory": True,
        "hard_bound_seconds": 110,
        "observed_at": ["before_refresh", "before_arch_audit", "after_report"],
    }
    payload["capabilities"] = dict(CAPABILITIES)
    return results.text_result(payload)
