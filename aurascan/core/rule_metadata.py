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
    agent_instruction = "agent_instruction"
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
    "SUPPLYCHAIN-AUR-JS-20260611": RuleMetadata("SUPPLYCHAIN-AUR-JS-20260611", RuleCategory.history_supply_chain, Severity.CRITICAL, "known-aur-campaign-payload", 100, True, "deterministic", "Installs a known malicious JavaScript dependency from the June 2026 AUR campaign."),
    "DEEPSTATIC-SUPPLYCHAIN-AUR-JS-20260611": RuleMetadata("DEEPSTATIC-SUPPLYCHAIN-AUR-JS-20260611", RuleCategory.history_supply_chain, Severity.CRITICAL, "known-aur-campaign-payload", 100, True, "deterministic", "Finds a known malicious JavaScript dependency in acquired source text."),
    "SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828": RuleMetadata("SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828", RuleCategory.history_supply_chain, Severity.CRITICAL, "known-aur-hyprland-fixes", 100, True, "deterministic", "Matches the source repository reported for the August 2026 hyprland-fixes backdoor."),
    "EXEC-INSTALL-HOOK-SUDO-001": RuleMetadata("EXEC-INSTALL-HOOK-SUDO-001", RuleCategory.deterministic_static, Severity.CRITICAL, "privileged-install-hook", 100, True, "deterministic", "Runs sudo directly from an already-privileged package install hook."),
    "PRIV-SUDOERS-NOPASSWD-001": RuleMetadata("PRIV-SUDOERS-NOPASSWD-001", RuleCategory.persistence, Severity.CRITICAL, "privileged-sudo-policy", 100, True, "deterministic", "Grants passwordless sudo execution."),
    "PRIV-SUDOERS-DROPIN-001": RuleMetadata("PRIV-SUDOERS-DROPIN-001", RuleCategory.persistence, Severity.HIGH, "privileged-sudo-policy", 85, True, "deterministic", "Installs or references a sudoers policy file."),
    "REMOTE-ADMIN-BACKDOOR-001": RuleMetadata("REMOTE-ADMIN-BACKDOOR-001", RuleCategory.network_behavior, Severity.CRITICAL, "remote-admin-backdoor", 100, True, "deterministic", "Correlates remote-access behavior with privilege, persistence, or anti-forensics."),
    "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001": RuleMetadata("DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001", RuleCategory.network_behavior, Severity.CRITICAL, "remote-admin-backdoor", 100, True, "deterministic", "Finds a correlated root remote-access backdoor chain in acquired source text."),
    "SEC-AUR-CAMPAIGN-BPF-PERSISTENCE": RuleMetadata("SEC-AUR-CAMPAIGN-BPF-PERSISTENCE", RuleCategory.persistence, Severity.CRITICAL, "known-aur-campaign-host-indicator", 100, True, "finding_fields", "Finds a campaign-associated eBPF persistence marker."),
    "SEC-AUR-CAMPAIGN-HISTORY-WINDOW": RuleMetadata("SEC-AUR-CAMPAIGN-HISTORY-WINDOW", RuleCategory.history_supply_chain, Severity.CRITICAL, "known-aur-campaign-history", 100, True, "finding_fields", "Correlates a listed package with the known campaign installation window."),
    "SEC-AUR-CAMPAIGN-INSTALLED-NAME": RuleMetadata("SEC-AUR-CAMPAIGN-INSTALLED-NAME", RuleCategory.history_supply_chain, Severity.MEDIUM, "known-aur-campaign-name", 75, True, "finding_fields", "Matches an installed package name to a historical campaign list."),
    "SEC-AUR-CAMPAIGN-PENDING-NAME": RuleMetadata("SEC-AUR-CAMPAIGN-PENDING-NAME", RuleCategory.history_supply_chain, Severity.MEDIUM, "known-aur-campaign-name", 75, True, "finding_fields", "Matches a pending AUR package name to a historical campaign list."),
    "SEC-AUR-CAMPAIGN-HELPER-CACHE": RuleMetadata("SEC-AUR-CAMPAIGN-HELPER-CACHE", RuleCategory.history_supply_chain, Severity.LOW, "known-aur-campaign-cache", 25, True, "finding_fields", "Matches an AUR helper cache directory to a historical campaign list."),
    "SEC-AUR-HYPRLAND-FIXES-HISTORY": RuleMetadata("SEC-AUR-HYPRLAND-FIXES-HISTORY", RuleCategory.history_supply_chain, Severity.CRITICAL, "known-aur-hyprland-fixes", 100, True, "finding_fields", "Finds a bounded pacman transaction for the reported hyprland-fixes package."),
    "SEC-AUR-HYPRLAND-FIXES-INSTALLED": RuleMetadata("SEC-AUR-HYPRLAND-FIXES-INSTALLED", RuleCategory.history_supply_chain, Severity.HIGH, "known-aur-hyprland-fixes", 95, True, "finding_fields", "Finds the reported package name in installed package state."),
    "SEC-AUR-HYPRLAND-FIXES-PENDING": RuleMetadata("SEC-AUR-HYPRLAND-FIXES-PENDING", RuleCategory.history_supply_chain, Severity.HIGH, "known-aur-hyprland-fixes", 95, True, "finding_fields", "Finds the reported package name in a pending transaction."),
    "SEC-AUR-HYPRLAND-FIXES-HELPER-CACHE": RuleMetadata("SEC-AUR-HYPRLAND-FIXES-HELPER-CACHE", RuleCategory.history_supply_chain, Severity.LOW, "known-aur-hyprland-fixes", 25, True, "finding_fields", "Finds the reported package name in an AUR helper cache."),
    "SEC-AUR-HYPRLAND-FIXES-HOST-ARTIFACTS": RuleMetadata("SEC-AUR-HYPRLAND-FIXES-HOST-ARTIFACTS", RuleCategory.persistence, Severity.CRITICAL, "known-aur-hyprland-fixes-host", 100, True, "finding_fields", "Finds exact reported files or correlated root remote-access behavior markers."),
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
    "AI-HEURISTIC-002": RuleMetadata("AI-HEURISTIC-002", RuleCategory.ai_review, Severity.MEDIUM, "ai-review", 45, True, "ai", "AI provider output violated the expected response contract and requires manual review."),
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
    "REC-UNSUPPORTED-TARGET": RuleMetadata("REC-UNSUPPORTED-TARGET", RuleCategory.incident_recovery, Severity.CRITICAL, "recovery-target", 100, True, "finding_fields", "The selected recovery target is not a supported Arch-family installation."),
    "REC-PACMAN-LOCK": RuleMetadata("REC-PACMAN-LOCK", RuleCategory.incident_recovery, Severity.MEDIUM, "recovery-package-manager", 65, True, "finding_fields", "A package database lock remains on the offline target."),
    "REC-REPOSITORY-BROKEN": RuleMetadata("REC-REPOSITORY-BROKEN", RuleCategory.incident_recovery, Severity.HIGH, "recovery-repository", 90, True, "finding_fields", "Package repository configuration has no active server."),
    "REC-PACMAN-INTERRUPTED": RuleMetadata("REC-PACMAN-INTERRUPTED", RuleCategory.incident_recovery, Severity.HIGH, "recovery-package-manager", 90, True, "finding_fields", "The latest bounded package history ends with an unresolved transaction failure."),
    "REC-INITRAMFS-MISSING": RuleMetadata("REC-INITRAMFS-MISSING", RuleCategory.incident_recovery, Severity.HIGH, "recovery-boot", 95, True, "finding_fields", "A matching kernel boot image could not be proven."),
    "REC-KERNEL-MODULES-MISSING": RuleMetadata("REC-KERNEL-MODULES-MISSING", RuleCategory.incident_recovery, Severity.CRITICAL, "recovery-kernel-module", 100, True, "finding_fields", "Kernel packages exist without matching module trees."),
    "REC-BOOT-CONFIG-DRIFT": RuleMetadata("REC-BOOT-CONFIG-DRIFT", RuleCategory.incident_recovery, Severity.HIGH, "recovery-boot", 90, True, "finding_fields", "Boot-critical packaged configuration changes remain unresolved."),
    "REC-BOOTLOADER-UNKNOWN": RuleMetadata("REC-BOOTLOADER-UNKNOWN", RuleCategory.incident_recovery, Severity.HIGH, "recovery-bootloader", 95, True, "finding_fields", "No supported bootloader and ESP pair was positively detected."),
    "REC-ROOT-SPACE": RuleMetadata("REC-ROOT-SPACE", RuleCategory.incident_recovery, Severity.HIGH, "recovery-disk-space", 85, True, "finding_fields", "The recovery target has critically low free space."),
}


_INSTRUCTION_GUARD_RULES = {
    "IG-ACTIVE-CLAUDE-DYNAMIC-COMMAND": (Severity.HIGH, "instruction-active-command", 95, "Claude dynamic command syntax is active agent control text."),
    "IG-ACTIVE-DANGEROUS-HOOK": (Severity.HIGH, "instruction-active-hook", 100, "An automatically activated agent hook contains a dangerous behavior family."),
    "IG-BEHAVIOR-CREDENTIAL-EXFILTRATION": (Severity.CRITICAL, "instruction-credential-transfer", 100, "Credential access is correlated with collection or transfer behavior."),
    "IG-BEHAVIOR-FETCH-EXECUTE": (Severity.HIGH, "instruction-fetch-execute", 100, "Agent control text correlates network retrieval with execution."),
    "IG-BEHAVIOR-OBFUSCATED-EXECUTION": (Severity.HIGH, "instruction-obfuscated-execution", 95, "Decoding or obfuscation is correlated with execution."),
    "IG-BEHAVIOR-PERSISTENT-DANGEROUS-ACTION": (Severity.HIGH, "instruction-persistence", 95, "Persistence or self-repair is correlated with a dangerous action."),
    "IG-BEHAVIOR-PRIVILEGE-ABUSE": (Severity.HIGH, "instruction-privilege", 100, "Agent control text requests password capture, sudo-policy weakening, or setuid behavior."),
    "IG-BEHAVIOR-STEALTH-ACTIVATION": (Severity.HIGH, "instruction-stealth", 95, "Automatic activation is correlated with concealment."),
    "IG-CONFIG-BROAD-TOOL-GRANT": (Severity.HIGH, "instruction-tool-grant", 85, "An agent configuration grants unusually broad shell or filesystem access."),
    "IG-CONFIG-INVALID-FRONTMATTER": (Severity.MEDIUM, "instruction-invalid-config", 60, "Agent Markdown has unterminated YAML frontmatter."),
    "IG-CONFIG-INVALID-JSON": (Severity.MEDIUM, "instruction-invalid-config", 70, "An agent configuration is not valid JSON."),
    "IG-CONFIG-INVALID-SHAPE": (Severity.MEDIUM, "instruction-invalid-config", 60, "An agent configuration has an unexpected JSON shape."),
    "IG-CONFIG-UNTERMINATED-FENCE": (Severity.MEDIUM, "instruction-invalid-config", 75, "Agent Markdown contains an unterminated fenced block."),
    "IG-INTEGRITY-BROKEN-SYMLINK": (Severity.MEDIUM, "instruction-link-integrity", 75, "An agent control file symlink is broken."),
    "IG-INTEGRITY-ANALYSIS-TRUNCATED": (Severity.MEDIUM, "instruction-analysis-bound", 90, "An agent control file exceeded a bounded import or text-analysis limit."),
    "IG-INTEGRITY-CONTENT-CHANGED": (Severity.MEDIUM, "instruction-content-change", 90, "A tracked agent control file changed since review."),
    "IG-INTEGRITY-CONTROL-MISSING": (Severity.MEDIUM, "instruction-content-change", 80, "A previously tracked agent control file is missing."),
    "IG-INTEGRITY-CONTROL-DIRECTORY-SYMLINK": (Severity.HIGH, "instruction-directory-integrity", 100, "A recognized AI-agent control directory is a symlink and was not traversed."),
    "IG-INTEGRITY-CONTROL-DIRECTORY-UNAVAILABLE": (Severity.HIGH, "instruction-directory-integrity", 95, "A recognized AI-agent control directory could not be enumerated safely."),
    "IG-INTEGRITY-CANDIDATE-OVERFLOW": (Severity.HIGH, "instruction-analysis-bound", 95, "The bounded continuation could not retain every imported agent resource."),
    "IG-INTEGRITY-CONTINUATION-RECOVERY": (Severity.MEDIUM, "instruction-analysis-bound", 90, "A stale continuation inventory was discarded after an interrupted scan."),
    "IG-INTEGRITY-CROSS-FILESYSTEM-OMISSION": (Severity.MEDIUM, "instruction-directory-integrity", 80, "A mounted directory is outside the bounded same-filesystem scan."),
    "IG-INTEGRITY-DIRECTORY-OMITTED": (Severity.MEDIUM, "instruction-directory-integrity", 90, "A queued directory or unstable entry could not be enumerated safely."),
    "IG-INTEGRITY-FINDING-OVERFLOW": (Severity.HIGH, "instruction-analysis-bound", 95, "The bounded report omitted additional integrity findings."),
    "IG-INTEGRITY-INVENTORY-OVERFLOW": (Severity.CRITICAL, "instruction-analysis-bound", 100, "The bounded report inventory omitted additional agent control files."),
    "IG-INTEGRITY-MANIFEST-OVERFLOW": (Severity.HIGH, "instruction-analysis-bound", 95, "The integrity manifest reached its tracked-file capacity."),
    "IG-INTEGRITY-IMPORT-MISSING": (Severity.MEDIUM, "instruction-import-integrity", 70, "An explicitly imported agent resource is unavailable."),
    "IG-INTEGRITY-IMPORT-NONTEXT": (Severity.MEDIUM, "instruction-import-integrity", 65, "An imported agent resource is not supported bounded text."),
    "IG-INTEGRITY-IMPORT-OUTSIDE-ROOT": (Severity.HIGH, "instruction-import-integrity", 100, "An explicit agent import leaves the selected root."),
    "IG-INTEGRITY-IMPORT-TYPE": (Severity.HIGH, "instruction-import-integrity", 95, "An imported agent resource is not a regular file."),
    "IG-INTEGRITY-MACHINE-BINDING": (Severity.MEDIUM, "instruction-baseline-binding", 90, "A restored baseline is not trusted on this machine and UID."),
    "IG-INTEGRITY-NONREGULAR-CONTROL": (Severity.HIGH, "instruction-file-integrity", 100, "An agent control path is a FIFO, device, socket, or other non-regular object."),
    "IG-INTEGRITY-SYMLINK-ESCAPE": (Severity.HIGH, "instruction-link-integrity", 100, "An agent control file symlink leaves the selected root."),
    "IG-INTEGRITY-SYMLINK-TYPE": (Severity.HIGH, "instruction-link-integrity", 95, "An agent control link does not resolve to a regular file."),
    "IG-INTEGRITY-UNREADABLE-CONTROL": (Severity.HIGH, "instruction-file-integrity", 95, "An agent control file failed bounded type, ownership, size, or replacement validation."),
}

RULE_METADATA.update({
    rule_id: RuleMetadata(
        rule_id,
        RuleCategory.agent_instruction,
        severity,
        group,
        priority,
        True,
        "finding_fields",
        description,
    )
    for rule_id, (severity, group, priority, description) in _INSTRUCTION_GUARD_RULES.items()
})


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
