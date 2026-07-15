from dataclasses import dataclass
from typing import Dict, Optional

from aurascan.core.models import Severity


class RuleCategory:
    source_metadata = "source_metadata"
    source_acquisition = "source_acquisition"
    checksum_integrity = "checksum_integrity"
    pgp_signature = "pgp_signature"
    clamav_signature = "clamav_signature"
    deterministic_static = "deterministic_static"
    credential_exposure = "credential_exposure"
    persistence = "persistence"
    network_behavior = "network_behavior"
    history_supply_chain = "history_supply_chain"
    ai_review = "ai_review"
    sandbox_runtime = "sandbox_runtime"
    archive_safety = "archive_safety"
    incident_recovery = "incident_recovery"
    unknown = "unknown"


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    category: str = RuleCategory.unknown
    default_severity: Optional[Severity] = None
    display_group: Optional[str] = None
    display_priority: int = 50
    show_by_default: bool = True
    template_key: Optional[str] = None
    description: str = ""


RULE_METADATA: Dict[str, RuleMetadata] = {
    "SOURCE-META-CHECKSUM-COUNT-MISMATCH": RuleMetadata(
        "SOURCE-META-CHECKSUM-COUNT-MISMATCH",
        RuleCategory.source_metadata,
        Severity.HIGH,
        "source-checksum-count",
        100,
        True,
        "finding_fields",
        "Source and checksum metadata counts differ.",
    ),
    "SOURCE-META-MISSING-CHECKSUM": RuleMetadata(
        "SOURCE-META-MISSING-CHECKSUM",
        RuleCategory.source_metadata,
        Severity.MEDIUM,
        "source-missing-checksum",
        75,
        True,
        "finding_fields",
        "A source entry lacks matching checksum metadata.",
    ),
    "SOURCE-META-WEAK-CHECKSUM": RuleMetadata(
        "SOURCE-META-WEAK-CHECKSUM",
        RuleCategory.checksum_integrity,
        Severity.MEDIUM,
        "source-weak-checksum",
        60,
        True,
        "finding_fields",
        "A remote source uses weak checksum metadata.",
    ),
    "SOURCE-META-HTTP-NOT-HTTPS": RuleMetadata(
        "SOURCE-META-HTTP-NOT-HTTPS",
        RuleCategory.source_metadata,
        Severity.MEDIUM,
        "source-http",
        65,
        True,
        "finding_fields",
        "A source URL uses plain HTTP.",
    ),
    "SOURCE-META-SKIP-ARCHIVE-NO-SIGNATURE": RuleMetadata(
        "SOURCE-META-SKIP-ARCHIVE-NO-SIGNATURE",
        RuleCategory.checksum_integrity,
        Severity.MEDIUM,
        "source-skip-archive",
        80,
        True,
        "finding_fields",
        "An archive source uses SKIP without a detached signature.",
    ),
    "SOURCE-META-SKIP-ARCHIVE-WITH-SIGNATURE": RuleMetadata(
        "SOURCE-META-SKIP-ARCHIVE-WITH-SIGNATURE",
        RuleCategory.pgp_signature,
        Severity.LOW,
        "source-signature-verification",
        30,
        False,
        "finding_fields",
        "An archive source relies on detached signature metadata.",
    ),
    "SOURCE-META-SKIP-GIT-COMMIT": RuleMetadata(
        "SOURCE-META-SKIP-GIT-COMMIT",
        RuleCategory.source_metadata,
        Severity.LOW,
        "source-git-pinning",
        10,
        False,
        "finding_fields",
        "A Git source is pinned to a commit and uses SKIP.",
    ),
    "SOURCE-META-SKIP-GIT-TAG": RuleMetadata(
        "SOURCE-META-SKIP-GIT-TAG",
        RuleCategory.source_metadata,
        Severity.MEDIUM,
        "source-git-pinning",
        35,
        False,
        "finding_fields",
        "A Git source uses a tag and SKIP.",
    ),
    "SOURCE-META-SKIP-GIT-BRANCH": RuleMetadata(
        "SOURCE-META-SKIP-GIT-BRANCH",
        RuleCategory.source_metadata,
        Severity.MEDIUM,
        "source-git-pinning",
        55,
        True,
        "finding_fields",
        "A Git source follows a branch and uses SKIP.",
    ),
    "SOURCE-META-SKIP-GIT-NO-FRAGMENT": RuleMetadata(
        "SOURCE-META-SKIP-GIT-NO-FRAGMENT",
        RuleCategory.source_metadata,
        Severity.MEDIUM,
        "source-git-pinning",
        70,
        True,
        "finding_fields",
        "A Git source has no commit, tag, or branch fragment.",
    ),
    "SOURCE-META-SIGNATURE-PRESENT": RuleMetadata(
        "SOURCE-META-SIGNATURE-PRESENT",
        RuleCategory.pgp_signature,
        Severity.LOW,
        "source-signature-metadata",
        20,
        False,
        "finding_fields",
        "Detached source signature metadata is present.",
    ),
    "SOURCE-META-WEAK-VALIDPGPKEY": RuleMetadata(
        "SOURCE-META-WEAK-VALIDPGPKEY",
        RuleCategory.pgp_signature,
        Severity.MEDIUM,
        "source-validpgpkeys",
        85,
        True,
        "finding_fields",
        "validpgpkeys uses a short or weak key identifier.",
    ),
    "SOURCE-META-VALIDPGPKEYS-MISSING": RuleMetadata(
        "SOURCE-META-VALIDPGPKEYS-MISSING",
        RuleCategory.pgp_signature,
        Severity.MEDIUM,
        "source-validpgpkeys",
        80,
        True,
        "finding_fields",
        "A detached source signature has no validpgpkeys metadata.",
    ),
    "SOURCE-UNSUPPORTED": RuleMetadata(
        "SOURCE-UNSUPPORTED",
        RuleCategory.source_acquisition,
        Severity.MEDIUM,
        "source-acquisition-unsupported",
        65,
        True,
        None,
        "Explicit source acquisition could not handle a source scheme.",
    ),
    "SOURCE-HTTP-FETCH-FAILED": RuleMetadata(
        "SOURCE-HTTP-FETCH-FAILED",
        RuleCategory.source_acquisition,
        Severity.MEDIUM,
        "source-acquisition-fetch",
        75,
        True,
        None,
        "HTTP or HTTPS source acquisition failed.",
    ),
    "SOURCE-GIT-FETCH-FAILED": RuleMetadata(
        "SOURCE-GIT-FETCH-FAILED",
        RuleCategory.source_acquisition,
        Severity.MEDIUM,
        "source-acquisition-fetch",
        75,
        True,
        None,
        "Git source acquisition failed.",
    ),
    "SOURCE-CHECKSUM-MISMATCH": RuleMetadata(
        "SOURCE-CHECKSUM-MISMATCH",
        RuleCategory.checksum_integrity,
        Severity.CRITICAL,
        "source-checksum-integrity",
        100,
        True,
        None,
        "Acquired source content did not match the declared checksum.",
    ),
    "SOURCE-CHECKSUM-SKIP": RuleMetadata(
        "SOURCE-CHECKSUM-SKIP",
        RuleCategory.checksum_integrity,
        Severity.MEDIUM,
        "source-checksum-integrity",
        75,
        True,
        None,
        "Source checksum verification is marked SKIP.",
    ),
    "SOURCE-CHECKSUM-MISSING": RuleMetadata(
        "SOURCE-CHECKSUM-MISSING",
        RuleCategory.checksum_integrity,
        Severity.MEDIUM,
        "source-checksum-integrity",
        70,
        True,
        None,
        "No checksum was declared for an acquired source.",
    ),
    "SIGNATURE-INVALID": RuleMetadata(
        "SIGNATURE-INVALID",
        RuleCategory.pgp_signature,
        Severity.CRITICAL,
        "source-signature-verification",
        100,
        True,
        None,
        "Detached source signature verification failed.",
    ),
    "SIGNATURE-FINGERPRINT-MISMATCH": RuleMetadata(
        "SIGNATURE-FINGERPRINT-MISMATCH",
        RuleCategory.pgp_signature,
        Severity.HIGH,
        "source-signature-verification",
        95,
        True,
        None,
        "Detached signature signer does not match validpgpkeys.",
    ),
    "SIGNATURE-VERIFIED": RuleMetadata(
        "SIGNATURE-VERIFIED",
        RuleCategory.pgp_signature,
        Severity.LOW,
        "source-signature-verification",
        20,
        False,
        None,
        "Detached signature verified against validpgpkeys.",
    ),
    "KEY_UNAVAILABLE": RuleMetadata(
        "KEY_UNAVAILABLE",
        RuleCategory.pgp_signature,
        Severity.MEDIUM,
        "source-signature-verification",
        70,
        True,
        None,
        "A validpgpkeys public key was unavailable.",
    ),
    "CLAMAV-TIMEOUT": RuleMetadata(
        "CLAMAV-TIMEOUT",
        RuleCategory.clamav_signature,
        Severity.HIGH,
        "clamav-scan",
        80,
        True,
        "clamav",
        "ClamAV scan timed out.",
    ),
    "CRED-SSH-001": RuleMetadata("CRED-SSH-001", RuleCategory.credential_exposure, Severity.CRITICAL, "credential-access", 100, True, "deterministic", "References SSH credential paths."),
    "CRED-GPG-001": RuleMetadata("CRED-GPG-001", RuleCategory.credential_exposure, Severity.CRITICAL, "credential-access", 100, True, "deterministic", "References GnuPG credential paths."),
    "CRED-ENV-001": RuleMetadata("CRED-ENV-001", RuleCategory.credential_exposure, Severity.HIGH, "credential-access", 90, True, "deterministic", "References environment secret files."),
    "NET-EXEC-001": RuleMetadata("NET-EXEC-001", RuleCategory.network_behavior, Severity.CRITICAL, "remote-execution", 100, True, "deterministic", "Pipes a network download to a shell."),
    "EXEC-B64-001": RuleMetadata("EXEC-B64-001", RuleCategory.deterministic_static, Severity.CRITICAL, "obfuscated-execution", 100, True, "deterministic", "Decodes base64 and executes it."),
    "EXEC-EVAL-NET-001": RuleMetadata("EXEC-EVAL-NET-001", RuleCategory.deterministic_static, Severity.CRITICAL, "dynamic-execution", 100, True, "deterministic", "Uses eval with network or decoded command content."),
    "EXEC-EVAL-001": RuleMetadata("EXEC-EVAL-001", RuleCategory.deterministic_static, Severity.HIGH, "dynamic-execution", 85, True, "deterministic", "Uses eval with dynamic shell content."),
    "SYS-CHMOD-001": RuleMetadata("SYS-CHMOD-001", RuleCategory.persistence, Severity.HIGH, "privileged-file-behavior", 90, True, "deterministic", "Attempts privileged chmod behavior."),
    "SYS-SYSTEMD-AUTO-001": RuleMetadata("SYS-SYSTEMD-AUTO-001", RuleCategory.persistence, Severity.HIGH, "systemd-service-behavior", 90, True, "deterministic", "Enables or starts a systemd service."),
    "SYS-SYSTEMD-USER-001": RuleMetadata("SYS-SYSTEMD-USER-001", RuleCategory.persistence, Severity.HIGH, "systemd-service-behavior", 88, True, "deterministic", "References user-level systemd persistence."),
    "SYS-SYSTEMD-UNIT-001": RuleMetadata("SYS-SYSTEMD-UNIT-001", RuleCategory.persistence, Severity.MEDIUM, "systemd-service-file", 40, True, "deterministic", "Installs or writes a systemd service unit."),
    "DEEPSTATIC-SYSTEMD-UNIT-001": RuleMetadata("DEEPSTATIC-SYSTEMD-UNIT-001", RuleCategory.persistence, Severity.MEDIUM, "deepstatic-systemd-unit", 35, True, None, "Source tree includes a systemd service or timer unit."),
    "DEEPSTATIC-SYSTEMD-AUTO-001": RuleMetadata("DEEPSTATIC-SYSTEMD-AUTO-001", RuleCategory.persistence, Severity.HIGH, "deepstatic-systemd-service-behavior", 88, True, None, "Source text enables or starts a systemd service."),
    "DEEPSTATIC-SYSTEMD-USER-001": RuleMetadata("DEEPSTATIC-SYSTEMD-USER-001", RuleCategory.persistence, Severity.HIGH, "deepstatic-systemd-service-behavior", 86, True, None, "Source text references user-level systemd persistence."),
    "SYS-CRON-FILE-001": RuleMetadata("SYS-CRON-FILE-001", RuleCategory.persistence, Severity.HIGH, "cron-persistence", 90, True, "deterministic", "Writes or references cron persistence locations."),
    "SYS-CRONTAB-001": RuleMetadata("SYS-CRONTAB-001", RuleCategory.persistence, Severity.HIGH, "cron-persistence", 88, True, "deterministic", "Uses the crontab command."),
    "SYS-CRON-REBOOT-001": RuleMetadata("SYS-CRON-REBOOT-001", RuleCategory.persistence, Severity.HIGH, "cron-persistence", 92, True, "deterministic", "Adds cron startup persistence."),
    "AI-HEURISTIC-001": RuleMetadata("AI-HEURISTIC-001", RuleCategory.ai_review, Severity.HIGH, "ai-review", 60, True, "ai", "AI review reported suspicious code."),
    "AI-HEURISTIC-002": RuleMetadata("AI-HEURISTIC-002", RuleCategory.ai_review, Severity.CRITICAL, "ai-review", 80, True, "ai", "AI provider output violated the expected response contract."),
    "AI-TIMEOUT": RuleMetadata("AI-TIMEOUT", RuleCategory.ai_review, Severity.MEDIUM, "ai-review", 35, True, "ai", "AI review timed out."),
    "PKG-EXTRACT-ERR": RuleMetadata("PKG-EXTRACT-ERR", RuleCategory.archive_safety, Severity.HIGH, "package-extraction", 80, True, None, "Package metadata extraction failed safely."),
    "ARCHIVE-PATH-TRAVERSAL": RuleMetadata("ARCHIVE-PATH-TRAVERSAL", RuleCategory.archive_safety, Severity.CRITICAL, "archive-safety", 100, True, None, "Archive entry would escape extraction directory."),
    "ARCHIVE-SYMLINK-ESCAPE": RuleMetadata("ARCHIVE-SYMLINK-ESCAPE", RuleCategory.archive_safety, Severity.CRITICAL, "archive-safety", 100, True, None, "Archive symlink can escape extraction directory."),
    "ARCHIVE-HARDLINK-ESCAPE": RuleMetadata("ARCHIVE-HARDLINK-ESCAPE", RuleCategory.archive_safety, Severity.CRITICAL, "archive-safety", 100, True, None, "Archive hardlink can escape extraction directory."),
    "ARCHIVE-TOO-MANY-FILES": RuleMetadata("ARCHIVE-TOO-MANY-FILES", RuleCategory.archive_safety, Severity.HIGH, "archive-limits", 90, True, None, "Archive exceeds file count limit."),
    "ARCHIVE-OVERSIZED": RuleMetadata("ARCHIVE-OVERSIZED", RuleCategory.archive_safety, Severity.HIGH, "archive-limits", 90, True, None, "Archive exceeds decompressed size limit."),
    "ARCHIVE-NESTED-DEPTH": RuleMetadata("ARCHIVE-NESTED-DEPTH", RuleCategory.archive_safety, Severity.HIGH, "archive-limits", 90, True, None, "Nested archive depth limit exceeded."),
    "INC-KERNEL-PANIC": RuleMetadata("INC-KERNEL-PANIC", RuleCategory.incident_recovery, Severity.CRITICAL, "incident-kernel", 100, True, "finding_fields", "Kernel panic evidence was recorded."),
    "INC-WATCHDOG": RuleMetadata("INC-WATCHDOG", RuleCategory.incident_recovery, Severity.HIGH, "incident-kernel", 95, True, "finding_fields", "A watchdog reset or CPU lockup was recorded."),
    "INC-OOM": RuleMetadata("INC-OOM", RuleCategory.incident_recovery, Severity.HIGH, "incident-memory", 85, True, "finding_fields", "The kernel or systemd killed a process to recover memory."),
    "INC-NVIDIA-ALLOCATION": RuleMetadata("INC-NVIDIA-ALLOCATION", RuleCategory.incident_recovery, Severity.MEDIUM, "incident-graphics", 70, True, "finding_fields", "The NVIDIA driver reported a memory-allocation failure that is not, by itself, proof of a system OOM event."),
    "INC-GPU-RESET": RuleMetadata("INC-GPU-RESET", RuleCategory.incident_recovery, Severity.HIGH, "incident-graphics", 85, True, "finding_fields", "The graphics driver reported a GPU reset or failure."),
    "INC-STORAGE-IO": RuleMetadata("INC-STORAGE-IO", RuleCategory.incident_recovery, Severity.CRITICAL, "incident-storage", 100, True, "finding_fields", "Storage I/O errors were recorded."),
    "INC-FILESYSTEM": RuleMetadata("INC-FILESYSTEM", RuleCategory.incident_recovery, Severity.HIGH, "incident-storage", 95, True, "finding_fields", "A filesystem reported corruption or forced read-only behavior."),
    "INC-THERMAL": RuleMetadata("INC-THERMAL", RuleCategory.incident_recovery, Severity.HIGH, "incident-hardware", 90, True, "finding_fields", "Thermal, power, or hardware-fault evidence was recorded."),
    "INC-PACKAGE-INTERRUPTED": RuleMetadata("INC-PACKAGE-INTERRUPTED", RuleCategory.incident_recovery, Severity.MEDIUM, "incident-package-manager", 70, True, "finding_fields", "A package transaction appears to have been interrupted."),
    "INC-DKMS": RuleMetadata("INC-DKMS", RuleCategory.incident_recovery, Severity.HIGH, "incident-kernel-module", 90, True, "finding_fields", "A kernel module or DKMS operation failed."),
    "INC-INITRAMFS": RuleMetadata("INC-INITRAMFS", RuleCategory.incident_recovery, Severity.HIGH, "incident-boot", 95, True, "finding_fields", "Initramfs generation failed."),
    "INC-DISK-FULL": RuleMetadata("INC-DISK-FULL", RuleCategory.incident_recovery, Severity.HIGH, "incident-disk-space", 85, True, "finding_fields", "A filesystem ran out of usable space."),
    "INC-REPOSITORY": RuleMetadata("INC-REPOSITORY", RuleCategory.incident_recovery, Severity.MEDIUM, "incident-repository", 65, True, "finding_fields", "Package repository access failed."),
    "INC-BOOT-UNCLEAN": RuleMetadata("INC-BOOT-UNCLEAN", RuleCategory.incident_recovery, Severity.MEDIUM, "incident-boot", 60, True, "finding_fields", "A previous boot may have ended unexpectedly."),
    "INC-SYSTEMD-FAILED": RuleMetadata("INC-SYSTEMD-FAILED", RuleCategory.incident_recovery, Severity.MEDIUM, "incident-service", 65, True, "finding_fields", "A systemd unit is currently failed."),
    "INC-APPLICATION-COREDUMP": RuleMetadata("INC-APPLICATION-COREDUMP", RuleCategory.incident_recovery, Severity.LOW, "incident-application", 45, True, "finding_fields", "An application or desktop component produced a coredump."),
    "INC-PSTORE-CRASH": RuleMetadata("INC-PSTORE-CRASH", RuleCategory.incident_recovery, Severity.HIGH, "incident-kernel", 98, True, "finding_fields", "Persistent low-level crash evidence was found in pstore."),
}


def get_rule_metadata(rule_id: str) -> Optional[RuleMetadata]:
    return RULE_METADATA.get(rule_id)


def get_display_group(rule_id: str) -> Optional[str]:
    metadata = get_rule_metadata(rule_id)
    return metadata.display_group if metadata else None


def get_display_priority(rule_id: str, default: int = 50) -> int:
    metadata = get_rule_metadata(rule_id)
    return metadata.display_priority if metadata else default


def has_known_template(rule_id: str) -> bool:
    metadata = get_rule_metadata(rule_id)
    return bool(metadata and metadata.template_key)


def is_known_rule(rule_id: str) -> bool:
    return rule_id in RULE_METADATA
