"""``security_audit``: bounded, offline host audit against packaged intelligence.

``readOnlyHint: true`` is honest only while ``offline=True``, ``refresh=False`` and the single
argv-only ``pacman -Q`` call site below hold. Adding a second call site, or a network argument, needs
a fresh annotation review.
"""

import subprocess
from pathlib import Path

from aurascan.core.security_audit import build_security_audit

from .. import results
from ..errors import ToolError

_ROOT = Path("/")

DEFAULT_MAX_FINDINGS = 100

CAPABILITIES = {
    "process": "one read-only `pacman -Q` query, explicit argv, 30 s package bound",
    "fs_read": (
        "stats or reads the reported artifact paths under /etc, /usr/lib, /usr/bin and "
        "/usr/local/bin, /root/pamkeys, /var/log/pacman.log{,.1}, /sys/fs/bpf and the AUR "
        "helper cache"
    ),
    "network": False,
    "state_writes": False,
    "offline": True,
}


def _runner(argv, **kwargs):
    """Injected runner. The body is a real ``subprocess.run`` call site, so the

    architecture audit records this module as a process owner.
    """
    return subprocess.run(argv, **kwargs)


def handle(ctx, arguments):
    max_findings = arguments.get("max_findings", DEFAULT_MAX_FINDINGS)
    include_evidence = bool(arguments.get("include_evidence", False))
    if ctx.cancelled():
        raise ToolError("cancelled", "cancelled before the audit started")

    try:
        report = build_security_audit(
            offline=True,
            refresh=False,
            state_root=None,
            home=Path.home(),
            root=_ROOT,
            include_host_indicators=True,
            include_arch_audit=True,
            runner=_runner,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolError("internal", "host audit failed: %s" % (exc,))

    if ctx.cancelled():
        raise ToolError("cancelled", "cancelled during the audit")

    payload = report.to_dict()
    all_findings = payload["findings"]
    truncated = len(all_findings) > max_findings
    payload["findings_truncated"] = truncated
    payload["findings"] = all_findings[:max_findings]
    if not include_evidence:
        for item in payload["findings"]:
            del item["evidence"]
    # Unreachable under ``offline=True``: the arch audit is skipped and never fills findings, so
    # its evidence is always dropped rather than promised.
    for item in payload["arch_audit"]["findings"]:
        del item["evidence"]

    payload["advisory"] = True
    payload["capabilities"] = dict(CAPABILITIES)
    return results.text_result(payload)
