from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

from aurascan.core.models import Finding, Severity
from aurascan.core.rule_metadata import RuleCategory, get_display_group, get_display_priority, get_rule_metadata


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

EXACT_TEMPLATES: Dict[str, Dict[str, str]] = {
    "HIST-MAINTAINER-CHANGED": {
        "title": "Package maintainer changed.",
        "summary": "This package is now maintained by a different AUR account than before.",
        "why": "This can be normal, for example when a package is handed over or adopted. It can also matter because a malicious update may come from a new maintainer after a takeover or adoption.",
        "action": "Review the update more carefully if this change appears together with source URL changes, removed signatures, new dependencies, or new install hooks.",
    },
    "HIST-ORPHAN-ADOPTED": {
        "title": "Orphaned package was adopted.",
        "summary": "This package appears to have moved from no maintainer to a new maintainer.",
        "why": "Adoption is common in the AUR, but it is also a moment when source or install behavior deserves a closer look.",
        "action": "Review this update more carefully if source URLs, verification settings, or install hooks changed at the same time.",
    },
    "HIST-SOURCE-URL-CHANGED": {
        "title": "Package source URL changed.",
        "summary": "This package now points to a different source URL than your previous scan.",
        "why": "Source moves can be legitimate, but they can also redirect builds to unexpected code.",
        "action": "Review the new source location, especially if the maintainer also changed or verification was weakened.",
    },
    "HIST-SOURCE-HOST-CHANGED": {
        "title": "Package source changed location.",
        "summary": "This package used to download source code from one host, but this update points somewhere else.",
        "why": "This can be legitimate, for example a project moving hosting providers. It can also be a warning sign if an update redirects source code to an unexpected fork, mirror, or personal account.",
        "action": "Review this update carefully, especially if the maintainer also changed or verification was weakened.",
    },
    "HIST-CHECKSUM-CHANGED": {
        "title": "Source checksum changed.",
        "summary": "The recorded source checksum changed since your previous scan.",
        "why": "Checksum changes are expected when upstream source changes, but they are also part of the source trust chain.",
        "action": "Review this together with source URL, maintainer, and signature changes.",
    },
    "HIST-CHECKSUM-WEAKENED": {
        "title": "Source checksum verification was weakened.",
        "summary": "This update uses weaker source integrity metadata than your previous scan.",
        "why": "Weakening checksum verification makes it harder to confirm that the downloaded source is the file the maintainer intended.",
        "action": "Treat this update with extra caution, especially if source location or maintainer also changed.",
    },
    "HIST-PGP-REMOVED": {
        "title": "Source signature verification was removed.",
        "summary": "This package previously declared signing keys or signature verification, but this update removed or weakened that verification.",
        "why": "Signatures help confirm that downloaded source files came from the expected upstream signer. Removing them does not prove malware, but it weakens integrity protection.",
        "action": "Treat this update with extra caution, especially if the source URL or maintainer also changed.",
    },
    "HIST-INSTALL-ADDED": {
        "title": "Package install script added.",
        "summary": "This package now includes an install hook that can run during installation, upgrade, or removal.",
        "why": "Install hooks are legitimate for some packages, but they are powerful because they can run commands when the package is installed.",
        "action": "Review the install hook contents before installing, especially if this appeared together with a maintainer or source change.",
    },
    "HIST-INSTALL-CHANGED": {
        "title": "Package install script changed.",
        "summary": "The package install hook changed since your previous scan.",
        "why": "Install hooks can run commands during install, upgrade, or removal.",
        "action": "Review the changed install hook before installing.",
    },
    "HIST-COMBINED-SUSPICIOUS-CHANGE": {
        "title": "Package update has multiple supply-chain risk signals.",
        "summary": "This update changed several trust-related parts of the package at the same time.",
        "why": "Each change can be legitimate by itself. Together, they deserve closer review because package takeover attacks often involve several small changes at once.",
        "checked": "AuraScan compared the current package metadata and build instructions with the previous local history snapshot.",
        "not_prove": "This does not prove malicious intent; it means the update has enough trust-related movement to deserve manual review.",
        "action": "Review the update before installing. Use --deep-static if you want AuraScan to fetch and inspect declared sources safely.",
    },
    "ARCHIVE-PATH-TRAVERSAL": {
        "title": "Source archive contains unsafe paths.",
        "summary": "AuraScan found archive entries that could try to extract files outside the intended temporary directory.",
        "why": "Malicious archives can use path tricks to overwrite files or escape the extraction directory.",
        "checked": "AuraScan inspected archive entry names before extraction.",
        "not_prove": "This does not prove who created the archive or why, but the archive is not safe to extract automatically.",
        "action": "Do not install this package unless the archive is manually reviewed and fixed.",
    },
    "ARCHIVE-SYMLINK-ESCAPE": {
        "title": "Source archive contains an unsafe symlink.",
        "summary": "AuraScan found a symbolic link in the archive that could point outside the extraction directory.",
        "why": "A crafted symlink can cause later extracted files or build steps to touch unexpected locations.",
        "checked": "AuraScan inspected symlink targets before extraction.",
        "not_prove": "This does not prove malicious intent, but it means automatic extraction would be unsafe.",
        "action": "Do not install this package unless the archive layout is manually reviewed and fixed.",
    },
    "ARCHIVE-HARDLINK-ESCAPE": {
        "title": "Source archive contains an unsafe hardlink.",
        "summary": "AuraScan found a hardlink in the archive that could point outside the extraction directory.",
        "why": "A crafted hardlink can make extraction write to an unexpected file path.",
        "checked": "AuraScan inspected hardlink targets before extraction.",
        "not_prove": "This does not prove malicious intent, but it means automatic extraction would be unsafe.",
        "action": "Do not install this package unless the archive layout is manually reviewed and fixed.",
    },
    "ARCHIVE-TOO-MANY-FILES": {
        "title": "Source archive contains too many files.",
        "summary": "AuraScan found more archive entries than its safe extraction policy allows.",
        "why": "Very large file counts can cause resource exhaustion or make source review impractical.",
        "checked": "AuraScan counted archive entries before extraction.",
        "not_prove": "This does not prove the archive is malicious; it means the archive is outside AuraScan's safe extraction budget.",
        "action": "Inspect the archive manually before trusting this package.",
    },
    "ARCHIVE-OVERSIZED": {
        "title": "Source archive exceeds the safe size limit.",
        "summary": "AuraScan found that the archive would expand beyond its configured decompressed size limit.",
        "why": "Oversized archives can exhaust disk or memory and can hide hard-to-review source trees.",
        "checked": "AuraScan summed declared archive entry sizes before extraction.",
        "not_prove": "This does not prove malicious intent; it means automatic extraction would exceed the safety budget.",
        "action": "Inspect the archive manually before trusting this package.",
    },
    "ARCHIVE-NESTED-DEPTH": {
        "title": "Source archive nesting is too deep.",
        "summary": "AuraScan found a nested archive beyond its configured safe inspection depth.",
        "why": "Deep archive nesting can hide payloads and make safe source inspection harder.",
        "checked": "AuraScan inspected archive structure and nesting depth before continuing extraction.",
        "not_prove": "This does not prove the nested archive is malicious; it means AuraScan stopped before exceeding its safe depth.",
        "action": "Inspect the nested archive manually before trusting this package.",
    },
    "DEEPSTATIC-NPM-INSTALL-SCRIPT": {
        "title": "Source declares an npm install-time script.",
        "summary": "AuraScan found a package.json script that can run during npm install or preparation.",
        "why": "Install-time scripts are powerful and can execute commands before a user reviews generated files.",
        "checked": "AuraScan parsed package.json as text and inspected script names without running them.",
        "not_prove": "This does not prove the script is malicious; many packages use install scripts for legitimate setup.",
        "action": "Review the script contents before installing or building this package.",
    },
    "DEEPSTATIC-SETUPPY-SUSPICIOUS": {
        "title": "setup.py contains network or process indicators.",
        "summary": "AuraScan found setup.py references to networking or subprocess behavior.",
        "why": "setup.py can execute during Python package build or installation, so network or process behavior deserves review.",
        "checked": "AuraScan inspected setup.py as text without executing it.",
        "not_prove": "This does not prove the setup.py behavior is malicious; it highlights code that can be risky if unexpected.",
        "action": "Review setup.py manually before trusting this source.",
    },
    "DEEPSTATIC-TOKEN-REFERENCE": {
        "title": "Source references token or private-key names.",
        "summary": "AuraScan found names commonly used for API tokens, secret keys, or private keys.",
        "why": "Build or install code should not normally need access to user tokens or private keys.",
        "checked": "AuraScan inspected source text for credential-related identifiers.",
        "not_prove": "This does not prove the package reads or exfiltrates secrets; it shows credential-sensitive names appear in source.",
        "action": "Review the surrounding code before installing or building this package.",
    },
    "EXEC-EVAL-001": {
        "title": "Package uses dynamic shell execution.",
        "summary": "AuraScan found shell code that uses eval or similar dynamic execution.",
        "why": "eval can run commands built from strings at build or install time. That can be legitimate in rare cases, but it also makes malicious behavior harder to review.",
        "checked": "AuraScan inspected package scripts and build metadata as text.",
        "not_prove": "This does not prove the package is malicious. It means the script contains behavior that deserves review.",
        "action": "Review the evidence before building or installing this package.",
    },
    "EXEC-EVAL-NET-001": {
        "title": "Package uses dynamic shell execution.",
        "summary": "AuraScan found eval combined with a network fetch or decoded shell content.",
        "why": "eval can run commands built from strings, and combining it with downloaded or decoded content makes behavior much harder to review before it runs.",
        "checked": "AuraScan inspected package scripts and build metadata as text.",
        "not_prove": "This does not prove who intended the behavior, but it is risky enough to block automatic installation.",
        "action": "Do not build or install this package unless you have manually reviewed and fully trust the command.",
    },
    "DEEPSTATIC-EVAL-CHAIN": {
        "title": "Package uses dynamic shell execution.",
        "summary": "AuraScan found source text that uses eval with dynamic command content.",
        "why": "eval can run commands built from strings at build or install time. That can be legitimate in rare cases, but it also makes malicious behavior harder to review.",
        "checked": "AuraScan inspected unpacked source files as text without executing them.",
        "not_prove": "This does not prove the package is malicious. It means the source contains behavior that deserves review.",
        "action": "Review the evidence before building or installing this package.",
    },
    "SYS-SYSTEMD-UNIT-001": {
        "title": "Package installs a systemd service file.",
        "summary": "AuraScan found package logic that installs or writes a systemd service unit.",
        "why": "Many daemon packages legitimately install service files. This is a lower-risk note unless the package also enables or starts the service automatically.",
        "checked": "AuraScan inspected package scripts and build metadata as static text.",
        "not_prove": "This does not prove malicious behavior. It means the package may add service metadata.",
        "action": "Review the service file if this package is new to you or other warnings appear.",
    },
    "SYS-SYSTEMD-AUTO-001": {
        "title": "Package may enable a system service.",
        "summary": "AuraScan found package logic related to enabling or starting a systemd service.",
        "why": "System services can run automatically in the background. Some packages need this, but automatically enabling or starting services during build or install deserves review.",
        "checked": "AuraScan inspected package scripts, install hooks, and source text as static text.",
        "not_prove": "This does not prove malicious behavior. It means the package may change background service behavior.",
        "action": "Review the service-related commands before installing.",
    },
    "SYS-SYSTEMD-USER-001": {
        "title": "Package may enable a user service.",
        "summary": "AuraScan found package logic related to user-level systemd persistence.",
        "why": "User services can run automatically in the background for a user account. Package build or install logic that writes user services deserves review.",
        "checked": "AuraScan inspected package scripts, install hooks, and source text as static text.",
        "not_prove": "This does not prove malicious behavior. It means the package may change background service behavior.",
        "action": "Review the service-related commands before installing.",
    },
    "DEEPSTATIC-SYSTEMD-UNIT-001": {
        "title": "Source includes a systemd service file.",
        "summary": "AuraScan found a systemd service or timer unit in the source tree.",
        "why": "Many daemon packages legitimately include unit files. This is a source review note, not proof of persistence or malware by itself.",
        "checked": "AuraScan inspected unpacked source file names as static text without executing them.",
        "not_prove": "This does not prove the service is enabled, started, or malicious.",
        "action": "Review the unit file if the package is new to you or other warnings appear.",
    },
    "DEEPSTATIC-SYSTEMD-AUTO-001": {
        "title": "Source may enable a system service.",
        "summary": "AuraScan found source text related to enabling or starting a systemd service.",
        "why": "System services can run automatically in the background. Some packages need this, but automatically enabling or starting services during build or install deserves review.",
        "checked": "AuraScan inspected unpacked source files as static text without executing them.",
        "not_prove": "This does not prove malicious behavior. It means the source may change background service behavior.",
        "action": "Review the service-related commands before installing.",
    },
    "DEEPSTATIC-SYSTEMD-USER-001": {
        "title": "Source may enable a user service.",
        "summary": "AuraScan found source text related to user-level systemd persistence.",
        "why": "User services can run automatically in the background for a user account. Source code that writes user services deserves review.",
        "checked": "AuraScan inspected unpacked source files as static text without executing them.",
        "not_prove": "This does not prove malicious behavior. It means the source may change background service behavior.",
        "action": "Review the user-service-related commands before installing.",
    },
    "DEEPSTATIC-SYSTEMD-PERSISTENCE": {
        "title": "Package may enable a system service.",
        "summary": "AuraScan found source text related to systemd service persistence.",
        "why": "System services can run automatically in the background. Some packages need this, but automatically enabling or starting services during build or install deserves review.",
        "checked": "AuraScan inspected unpacked source files as static text without executing them.",
        "not_prove": "This does not prove malicious behavior. It means the source may change background service behavior.",
        "action": "Review the service-related commands before installing.",
    },
    "SYS-CRON-FILE-001": {
        "title": "Package may add a scheduled background task.",
        "summary": "AuraScan found package logic related to cron, which can run commands automatically on a schedule or at login/startup.",
        "why": "Scheduled tasks can be legitimate, but they can also be used for persistence.",
        "checked": "AuraScan inspected package scripts and install hooks as static text.",
        "not_prove": "This does not prove malicious behavior. It means the package may add background scheduled behavior.",
        "action": "Review the cron-related commands before installing.",
    },
    "SYS-CRONTAB-001": {
        "title": "Package may add a scheduled background task.",
        "summary": "AuraScan found package logic that uses the crontab command.",
        "why": "Scheduled tasks can be legitimate, but they can also be used for persistence.",
        "checked": "AuraScan inspected package scripts and install hooks as static text.",
        "not_prove": "This does not prove malicious behavior. It means the package may add background scheduled behavior.",
        "action": "Review the cron-related commands before installing.",
    },
    "SYS-CRON-REBOOT-001": {
        "title": "Package may add a scheduled background task.",
        "summary": "AuraScan found a cron @reboot entry, which can run commands automatically at startup.",
        "why": "Scheduled tasks can be legitimate, but they can also be used for persistence.",
        "checked": "AuraScan inspected package scripts and install hooks as static text.",
        "not_prove": "This does not prove malicious behavior. It means the package may add background scheduled behavior.",
        "action": "Review the cron-related commands before installing.",
    },
    "DEEPSTATIC-CRON-PERSISTENCE": {
        "title": "Package may add a scheduled background task.",
        "summary": "AuraScan found source text related to cron, which can run commands automatically on a schedule or at startup.",
        "why": "Scheduled tasks can be legitimate, but they can also be used for persistence.",
        "checked": "AuraScan inspected unpacked source files as static text without executing them.",
        "not_prove": "This does not prove malicious behavior. It means the source may add background scheduled behavior.",
        "action": "Review the cron-related commands before installing.",
    },
    "PKG-EXTRACT-ERR": {
        "title": "Package metadata extraction was blocked.",
        "summary": "AuraScan stopped metadata extraction because the package data exceeded a safety limit or could not be safely read.",
        "why": "Extraction limits help prevent denial-of-service behavior and unsafe parsing of oversized package metadata.",
        "checked": "AuraScan attempted to read package metadata using bounded extraction.",
        "not_prove": "This does not prove the package is malicious; it means AuraScan could not complete this check safely.",
        "action": "Inspect the package manually before installing.",
    },
    "SIGNATURE-INVALID": {
        "title": "Source signature verification failed.",
        "summary": "AuraScan found a detached signature for the source file, but the signature did not verify.",
        "why": "A failed signature means AuraScan could not confirm that the source file matches the expected upstream signer.",
        "checked": "AuraScan verified the signature inside an isolated temporary GPG environment.",
        "not_prove": "This does not prove malicious intent by itself, but it means the source is not verified as expected.",
        "action": "Do not install this package unless you independently verify the source.",
    },
    "SIGNATURE-FINGERPRINT-MISMATCH": {
        "title": "Source was signed by an unexpected key.",
        "summary": "The source signature is valid, but it was not signed by one of the fingerprints declared in validpgpkeys.",
        "why": "This can happen after legitimate upstream key changes, but it can also indicate that the source came from a different signer than expected.",
        "checked": "AuraScan verified the detached signature and compared the signer fingerprint with validpgpkeys.",
        "not_prove": "This does not prove the source is malicious; it means the signer trust anchor did not match the package metadata.",
        "action": "Review the upstream key change before installing.",
    },
    "SOURCE-CHECKSUM-MISMATCH": {
        "title": "Downloaded source does not match the expected checksum.",
        "summary": "AuraScan downloaded a declared source file, but its checksum did not match the checksum listed by the package.",
        "why": "A checksum mismatch can mean the source changed, the package is outdated, or the download was tampered with.",
        "checked": "AuraScan hashed the downloaded file and compared it with the package metadata.",
        "not_prove": "This does not prove malicious intent by itself, but it means the file is not the expected one.",
        "action": "Do not install this package unless you manually verify the source and package metadata.",
    },
    "SOURCE-HTTP-FETCH-FAILED": {
        "title": "Source download failed during deep source acquisition.",
        "summary": "AuraScan could not download a declared HTTP or HTTPS source while running an explicit source-acquisition mode.",
        "why": "If source acquisition fails, AuraScan cannot inspect or verify that source content.",
        "checked": "AuraScan attempted a bounded HTTP or HTTPS fetch with redirect and size controls.",
        "not_prove": "This does not prove the source is malicious; the host may be unavailable or the package metadata may be stale.",
        "action": "Retry later or manually verify the source before installing.",
    },
    "SOURCE-GIT-FETCH-FAILED": {
        "title": "Git source acquisition failed.",
        "summary": "AuraScan could not fetch a declared Git source while running an explicit source-acquisition mode.",
        "why": "If Git acquisition fails, AuraScan cannot inspect the repository contents or verify the requested revision.",
        "checked": "AuraScan attempted a bounded Git fetch for the declared source.",
        "not_prove": "This does not prove the repository is malicious; the network, host, or ref may have failed.",
        "action": "Manually verify the repository and requested ref before installing.",
    },
    "SOURCE-GIT-COMMIT-NOT-FULL": {
        "title": "Git source is pinned with a short commit identifier.",
        "summary": "AuraScan found a Git source commit fragment that is not a full commit hash.",
        "why": "Short commit IDs are weaker identifiers because they can become ambiguous as a repository grows.",
        "checked": "AuraScan inspected the declared Git source fragment without executing package code.",
        "not_prove": "This does not prove the source is malicious; it means the pin is less precise than a full commit hash.",
        "action": "Prefer a full commit hash before relying on automated source acquisition.",
    },
    "SOURCE-GIT-BRANCH": {
        "title": "Git source follows a moving branch.",
        "summary": "AuraScan found a Git source pinned to a branch instead of a fixed commit.",
        "why": "Branches can change over time, so two builds of the same package may use different source code.",
        "checked": "AuraScan inspected the declared Git source fragment during source acquisition.",
        "not_prove": "This does not prove the branch is malicious; it means the source is not fixed to immutable content.",
        "action": "Review the repository and prefer a full commit pin for stronger reproducibility.",
    },
    "SOURCE-GIT-UNPINNED": {
        "title": "Git source is not pinned to a fixed revision.",
        "summary": "AuraScan found a Git source without a commit, tag, or branch fragment.",
        "why": "Unpinned Git sources can change between builds without the package metadata changing.",
        "checked": "AuraScan inspected the declared Git source URL during source acquisition.",
        "not_prove": "This does not prove the source is malicious; it means AuraScan cannot tie the build to a stable revision.",
        "action": "Review the repository and prefer a full commit pin before installing.",
    },
    "ARCHIVE-UNSUPPORTED": {
        "title": "Source archive format is not supported.",
        "summary": "AuraScan could not inspect this archive because its format is not supported by the safe extractor.",
        "why": "Unsupported archive formats cannot be checked for unsafe paths, excessive size, or nested content by this scanner.",
        "checked": "AuraScan checked whether the file was a supported tar or zip archive before extraction.",
        "not_prove": "This does not prove the archive is unsafe; it means AuraScan could not complete archive safety checks.",
        "action": "Inspect the archive manually or use a supported source format.",
    },
    "ARCHIVE-SUSPICIOUS-FILE": {
        "title": "Source archive contains a file worth reviewing.",
        "summary": "AuraScan found an executable or hidden script-like file inside the archive.",
        "why": "These files can be legitimate, but they can also hide build or install behavior that deserves a closer look.",
        "checked": "AuraScan inspected archive entry names and executable bits before extraction.",
        "not_prove": "This does not prove the file is malicious; it only highlights a file that may need review.",
        "action": "Review the listed file before trusting this source.",
    },
    "DEEPSTATIC-BINARY-BLOB": {
        "title": "Source tree contains a binary file.",
        "summary": "AuraScan found a binary-looking file in the unpacked source tree.",
        "why": "Binary files are harder to audit than source code and can contain prebuilt behavior that is not visible in text review.",
        "checked": "AuraScan inspected source files for binary indicators without executing them.",
        "not_prove": "This does not prove the binary is malicious; it means the source is less transparent.",
        "action": "Verify that the binary is expected and documented before installing.",
    },
    "DEEPSTATIC-HEREDOC-PAYLOAD": {
        "title": "Source contains a suspicious heredoc payload.",
        "summary": "AuraScan found a heredoc block combined with behavior such as network access, base64 decoding, or permission changes.",
        "why": "Heredocs are normal shell syntax, but they can also be used to hide generated scripts or payloads inside build logic.",
        "checked": "AuraScan inspected source text for heredoc patterns and nearby risky commands.",
        "not_prove": "This does not prove the heredoc is malicious; it means the generated content deserves review.",
        "action": "Review the surrounding script before trusting this source.",
    },
    "DEEPSTATIC-TYPOSQUAT-INDICATOR": {
        "title": "Dependency name looks similar to a common package.",
        "summary": "AuraScan found a dependency name that resembles a known typo-style package name.",
        "why": "Typosquatting can trick users or build systems into installing an unintended dependency.",
        "checked": "AuraScan inspected package metadata text for known typo-like dependency names.",
        "not_prove": "This does not prove the dependency is malicious; it means the dependency name should be verified.",
        "action": "Check that the dependency is the intended package before installing.",
    },
    "SIGNATURE-FILE-MISSING": {
        "title": "Signature file could not be found.",
        "summary": "This package declares a detached signature, but AuraScan could not find or acquire the signature file.",
        "why": "Without the signature file, AuraScan cannot verify the signed source automatically.",
        "checked": "AuraScan looked for the declared signature source during source acquisition.",
        "not_prove": "This does not prove the package is malicious. It means signature verification could not be completed automatically.",
        "action": "Check the source metadata or verify the signature manually before installing.",
    },
    "SIGNATURE-MISSING": {
        "title": "Signing key declared, but no signature was found.",
        "summary": "This package declares expected signing keys, but AuraScan did not find a matching detached signature source.",
        "why": "The package may have incomplete verification metadata, or the signature may be provided in a way AuraScan does not yet understand.",
        "checked": "AuraScan inspected the source and signature metadata.",
        "not_prove": "This does not prove a problem by itself, but signature verification could not be completed from the visible metadata.",
        "action": "Review the source metadata. Use --deep-static for a closer check when available.",
    },
    "SIGNATURE-VERIFICATION-ERROR": {
        "title": "Signature verification could not run.",
        "summary": "AuraScan found signature metadata, but an error stopped automatic verification.",
        "why": "When verification cannot run, AuraScan cannot confirm that the source matches the expected signer.",
        "checked": "AuraScan attempted to run detached signature verification in an isolated GPG environment.",
        "not_prove": "This does not prove the package is malicious; it means the verification step did not complete.",
        "action": "Retry the scan or manually verify the source signature.",
    },
    "SIGNATURE-VERIFICATION-UNAVAILABLE": {
        "title": "Signature verification is unavailable.",
        "summary": "AuraScan could not verify the detached signature because the local verification tool is unavailable.",
        "why": "Without a working verifier, AuraScan cannot confirm that the signature matches the source and expected signer.",
        "checked": "AuraScan checked whether signature verification tooling was available.",
        "not_prove": "This does not prove the package is malicious. It means this verification check could not be performed automatically.",
        "action": "Install GnuPG or manually verify the source signature.",
    },
    "SOURCE-CHECKSUM-MISSING": {
        "title": "Source checksum is missing.",
        "summary": "AuraScan found a source entry without a declared checksum.",
        "why": "Checksums help confirm that downloaded source files match the package metadata.",
        "checked": "AuraScan inspected source and checksum metadata.",
        "not_prove": "This does not prove the source is unsafe; it means AuraScan has less integrity information for this source.",
        "action": "Review the source manually or prefer packages with checksum or signature verification.",
    },
    "SOURCE-GIT-TAG": {
        "title": "Git source uses a tag.",
        "summary": "AuraScan found a Git source pinned to a tag rather than a full commit hash.",
        "why": "Tags are usually stable, but some tags can be moved unless upstream protects them.",
        "checked": "AuraScan inspected the declared Git source fragment during source acquisition.",
        "not_prove": "This does not prove the tag is unsafe; it means the source is less strict than a full commit pin.",
        "action": "Review the upstream tag or prefer a full commit hash for stronger reproducibility.",
    },
    "SOURCE-GIT-UNAVAILABLE": {
        "title": "Git is unavailable for source acquisition.",
        "summary": "AuraScan could not acquire a Git source because the git command is not available.",
        "why": "Without Git, AuraScan cannot inspect repository sources in deep source-acquisition mode.",
        "checked": "AuraScan checked for Git before attempting repository acquisition.",
        "not_prove": "This does not prove the source is unsafe; it means this source could not be checked automatically.",
        "action": "Install Git or manually review the declared repository source.",
    },
    "SOURCE-LOCAL-MISSING": {
        "title": "Declared local source is missing.",
        "summary": "AuraScan could not find a local source file declared by the package.",
        "why": "Missing local sources prevent AuraScan from inspecting or verifying all files involved in the build.",
        "checked": "AuraScan resolved the local source path relative to the package directory.",
        "not_prove": "This does not prove the package is malicious; it means the local source set is incomplete for this scan.",
        "action": "Check out the full package directory or review the missing source manually.",
    },
    "SOURCE-PARSER-AMBIGUOUS": {
        "title": "Source metadata uses dynamic shell syntax.",
        "summary": "AuraScan found source declarations that require shell evaluation to resolve safely.",
        "why": "AuraScan does not execute PKGBUILD shell code during parsing, so dynamic source metadata can be ambiguous.",
        "checked": "AuraScan inspected the source array text without running package code.",
        "not_prove": "This does not prove the source is unsafe; it means AuraScan refused to guess at shell-expanded source values.",
        "action": "Review the source declaration manually before installing.",
    },
    "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS": {
        "title": "Signature found, but expected signing key is not declared.",
        "summary": "This package includes a detached signature, but it does not clearly declare which signing key AuraScan should expect.",
        "why": "A signature is most useful when it can be matched to a known expected fingerprint.",
        "checked": "AuraScan found signature metadata in the package.",
        "not_prove": "AuraScan did not confirm that the signature belongs to the intended upstream signer.",
        "action": "Review the package metadata or run --deep-static if verification data is available.",
    },
    "SOURCE-UNSUPPORTED": {
        "title": "Source type is not supported for automatic acquisition.",
        "summary": "AuraScan found a declared source form that this explicit source-acquisition mode does not currently handle.",
        "why": "Unsupported source types reduce coverage because AuraScan cannot fetch or inspect that source automatically.",
        "checked": "AuraScan classified the declared source without executing package code.",
        "not_prove": "This does not prove the source is unsafe; it means this source needs manual review or future tool support.",
        "action": "Review the listed source manually before installing.",
    },
    "SOURCE-VALIDPGPKEY-WEAK": {
        "title": "Signing key identifier is too short.",
        "summary": "This package declares a signing key using a short key ID instead of a full fingerprint.",
        "why": "Short key IDs are easier to confuse than full fingerprints.",
        "checked": "AuraScan normalized and inspected validpgpkeys metadata.",
        "not_prove": "This does not prove the key is wrong; it means the signing-key identifier is weaker than preferred.",
        "action": "Prefer packages that declare full signing-key fingerprints.",
    },
    "KEY_UNAVAILABLE": {
        "title": "Signing key could not be found.",
        "summary": "This package declares a source signature, but AuraScan could not find the public key needed to verify it.",
        "why": "Without the public key, AuraScan cannot confirm that the signature belongs to the expected signer.",
        "checked": "AuraScan looked for the key using the configured key sources and automatic key fetching policy.",
        "not_prove": "This does not prove the package is malicious. It means the signature could not be checked automatically.",
        "action": "Use --deep-static again later, check your network or keyserver settings, or manually verify the upstream signing key.",
    },
}

DETERMINISTIC_TITLES = {
    "CRED-SSH-001": "Package tries to access user secrets.",
    "CRED-GPG-001": "Package tries to access user secrets.",
    "CRED-ENV-001": "Package references environment secret files.",
    "NET-EXEC-001": "Package downloads code and pipes it to a shell.",
    "EXEC-B64-001": "Package decodes base64 and executes it.",
    "SYS-CHMOD-001": "Package tries to create privileged executable behavior.",
    "DEEPSTATIC-CREDENTIAL-PATH": "Source references user secrets.",
    "DEEPSTATIC-SYSTEMD-UNIT-001": "Source includes a systemd service file.",
    "DEEPSTATIC-SYSTEMD-AUTO-001": "Source may enable a system service.",
    "DEEPSTATIC-SYSTEMD-USER-001": "Source may enable a user service.",
    "DEEPSTATIC-SYSTEMD-PERSISTENCE": "Source contains systemd persistence indicators.",
    "DEEPSTATIC-CRON-PERSISTENCE": "Source contains cron persistence indicators.",
    "DEEPSTATIC-SUID-LOGIC": "Source contains privileged permission changes.",
    "DEEPSTATIC-NETWORK-FETCH": "Source contains an additional network fetch.",
    "DEEPSTATIC-BASE64-EXEC": "Source decodes base64 and executes it.",
    "DEEPSTATIC-EVAL-CHAIN": "Source contains an eval chain.",
    "DEEPSTATIC-OBFUSCATED-CODE": "Source contains obfuscation indicators.",
}

SECTION_ORDER = [
    "Critical blockers",
    "Supply-chain history",
    "Source metadata",
    "Signatures and checksums",
    "Malware signatures",
    "Static code findings",
    "AI review",
    "Other findings",
]


def has_presenter_template(rule_id: str) -> bool:
    return (
        rule_id.startswith("CLAMAV-")
        or rule_id.startswith("AI-")
        or rule_id in EXACT_TEMPLATES
        or rule_id in DETERMINISTIC_TITLES
        or (rule_id.endswith("-ADDED") and "DEPENDS" in rule_id)
        or (rule_id.startswith("HIST-") and rule_id.endswith("-CHANGED"))
        or (rule_id.startswith("HIST-") and rule_id.endswith("-NEW-NETWORK"))
    )


def known_presenter_template_rules() -> List[str]:
    return sorted(set(EXACT_TEMPLATES) | set(DETERMINISTIC_TITLES) | {"CLAMAV-*", "AI-*", "HIST-*-CHANGED", "HIST-*-NEW-NETWORK", "HIST-*DEPENDS*-ADDED"})


@dataclass
class PresentedFinding:
    title: str
    summary: str
    why_it_matters: str
    checked: str
    not_prove: str
    recommended_action: str
    findings: List[Finding]
    severity: Severity
    priority: int
    synthetic: bool = False
    section: str = "Other findings"


class FindingPresenter:
    def __init__(self, max_groups: int = 3):
        self.max_groups = max_groups

    def render(self, findings: Iterable[Finding], *, verbose: bool = False) -> Tuple[List[str], int]:
        findings = list(findings)
        groups = self._groups(findings)
        if not groups:
            return [], 0

        visible = []
        hidden = []
        for item in groups:
            if verbose or self._show_group_by_default(item):
                visible.append(item)
            else:
                hidden.append(item)

        protected_visible = [g for g in visible if g.severity in (Severity.HIGH, Severity.CRITICAL)]
        lower_visible = [g for g in visible if g.severity not in (Severity.HIGH, Severity.CRITICAL)]
        if not verbose and len(lower_visible) > self.max_groups:
            kept = lower_visible[:self.max_groups]
            hidden.extend(lower_visible[self.max_groups:])
            visible = protected_visible + kept

        lines: List[str] = []
        if visible:
            warning_count = sum(1 for group in visible if any(f.requires_manual_review or f.blocks_installation for f in group.findings))
            label = "warning needs attention" if warning_count == 1 else "warnings need attention"
            lines.append("Warnings:")
            lines.append(f"{warning_count or len(visible)} {label}")
            lines.append("")

        current_section = ""
        for index, group in enumerate(visible):
            if group.section != current_section:
                if index:
                    lines.append("")
                lines.append(f"{group.section}:")
                current_section = group.section
            elif index:
                lines.append("")
            lines.append(group.title)
            if group.summary:
                lines.append(group.summary)
            if group.why_it_matters:
                lines.append(f"Why it matters: {group.why_it_matters}")
            if group.checked:
                lines.append(f"What AuraScan checked: {group.checked}")
            if group.not_prove:
                lines.append(f"What AuraScan did not prove: {group.not_prove}")
            if group.recommended_action:
                lines.append(f"Recommended action: {group.recommended_action}")
            if verbose:
                lines.append("Technical details:")
                for finding in group.findings:
                    detail = finding.technical_details or finding.evidence_snippet or finding.file_path
                    lines.append(f"- {finding.rule_id} ({finding.severity.value}): {detail}")

        if hidden and not verbose:
            note = "lower-risk note hidden" if len(hidden) == 1 else "lower-risk notes hidden"
            lines.append("")
            lines.append(f"{len(hidden)} {note}. Use --verbose to show them.")

        return lines, len(hidden)

    def _groups(self, findings: Iterable[Finding]) -> List[PresentedFinding]:
        findings = list(findings)
        grouped: Dict[str, List[Finding]] = {}
        for finding in findings:
            key = finding.display_group or get_display_group(finding.rule_id) or finding.user_title or finding.rule_id
            grouped.setdefault(key, []).append(finding)

        presented = [self._present_group(items) for items in grouped.values()]
        combined = self._combined_history_group(findings)
        if combined:
            presented.insert(0, combined)
            for item in presented[1:]:
                if (
                    item.severity not in (Severity.HIGH, Severity.CRITICAL)
                    and any(finding in combined.findings for finding in item.findings)
                ):
                    for finding in item.findings:
                        finding.show_by_default = False
        return sorted(
            presented,
            key=lambda item: (
                0 if item.section == "Critical blockers" else 1,
                SECTION_ORDER.index(item.section) if item.section in SECTION_ORDER else len(SECTION_ORDER),
                0 if item.synthetic else 1,
                -item.priority,
                -_SEVERITY_ORDER.index(item.severity),
                item.title,
            ),
        )

    def _present_group(self, findings: List[Finding]) -> PresentedFinding:
        highest = max((finding.severity for finding in findings), key=_SEVERITY_ORDER.index)
        primary = max(findings, key=lambda f: (get_display_priority(f.rule_id, f.display_priority), _SEVERITY_ORDER.index(f.severity)))
        template = self._template(primary)
        has_specific_text = bool(primary.user_title or template)
        title = primary.user_title or template.get("title") or self._fallback_title(primary)
        summary = primary.user_summary or template.get("summary") or (primary.explanation if has_specific_text else self._fallback_summary(primary))
        why = primary.why_it_matters or template.get("why") or ("" if has_specific_text else self._fallback_why(primary))
        checked = primary.what_aurascan_checked or template.get("checked") or ""
        not_prove = primary.what_aurascan_did_not_check or template.get("not_prove") or ""
        action = primary.recommended_user_action or template.get("action") or (primary.recommendation if has_specific_text else self._fallback_action(primary))
        return PresentedFinding(
            title=title,
            summary=summary,
            why_it_matters=why,
            checked=checked,
            not_prove=not_prove,
            recommended_action=action,
            findings=findings,
            severity=highest,
            priority=max(get_display_priority(f.rule_id, f.display_priority) for f in findings),
            section=self._section_for(primary, highest),
        )

    def _combined_history_group(self, findings: List[Finding]) -> PresentedFinding:
        history = [finding for finding in findings if finding.rule_id.startswith("HIST-")]
        rule_ids = {finding.rule_id for finding in history}
        combos = [
            {"HIST-MAINTAINER-CHANGED", "HIST-SOURCE-HOST-CHANGED"},
            {"HIST-MAINTAINER-CHANGED", "HIST-SOURCE-URL-CHANGED"},
            {"HIST-MAINTAINER-CHANGED", "HIST-PGP-REMOVED"},
            {"HIST-MAINTAINER-CHANGED", "HIST-INSTALL-ADDED"},
            {"HIST-SOURCE-HOST-CHANGED", "HIST-CHECKSUM-WEAKENED"},
            {"HIST-SOURCE-HOST-CHANGED", "HIST-PGP-REMOVED"},
            {"HIST-ORPHAN-ADOPTED", "HIST-SOURCE-URL-CHANGED"},
            {"HIST-ORPHAN-ADOPTED", "HIST-INSTALL-ADDED"},
            {"HIST-BUILD-CHANGED", "HIST-BUILD-NEW-NETWORK"},
            {"HIST-PACKAGE-CHANGED", "HIST-PACKAGE-NEW-NETWORK"},
        ]
        dependency_added = any(rule_id.endswith("-ADDED") and "DEPENDS" in rule_id for rule_id in rule_ids)
        matched = any(combo <= rule_ids for combo in combos)
        matched = matched or (dependency_added and "HIST-MAINTAINER-CHANGED" in rule_ids)
        matched = matched or "HIST-COMBINED-SUSPICIOUS-CHANGE" in rule_ids
        if not matched:
            return None

        severity = Severity.HIGH if any(f.severity == Severity.HIGH for f in history) else Severity.MEDIUM
        return PresentedFinding(
            title="Package update has multiple supply-chain risk signals.",
            summary="This update changed more than one trust-related part of the package, such as maintainer, source location, dependencies, or verification settings.",
            why_it_matters="Each change can be legitimate by itself. Together, they deserve closer review because package takeover attacks often involve several small changes at once.",
            checked="AuraScan compared this package against the previous local history snapshot.",
            not_prove="This does not prove the update is malicious; it shows several trust-related changes happened together.",
            recommended_action="Review this update before installing. Use --deep-static if you want AuraScan to fetch and inspect declared sources safely.",
            findings=history,
            severity=severity,
            priority=1000,
            synthetic=True,
            section="Supply-chain history",
        )

    def _template(self, finding: Finding) -> Dict[str, str]:
        if finding.rule_id.startswith("CLAMAV-"):
            return {
                "title": "Known malware signature detected.",
                "summary": "ClamAV matched this file against a known malware signature.",
                "why": "This is stronger evidence than a heuristic warning because it matched a known signature database entry.",
                "action": "Do not install this package unless you have a specific reason and can independently verify the file.",
            }
        if finding.source.value == "ai_review" or finding.rule_id.startswith("AI-"):
            return {
                "title": "AI review found suspicious code.",
                "summary": "AuraScan's AI review found code that looks suspicious, but this is not a confirmed malware signature.",
                "why": "AI review can help spot patterns worth checking, but it can be wrong and must not override deterministic evidence.",
                "action": "Review the evidence manually and look for matching deterministic findings before deciding.",
            }

        if finding.rule_id in EXACT_TEMPLATES:
            return EXACT_TEMPLATES[finding.rule_id]
        if finding.rule_id.endswith("-ADDED") and "DEPENDS" in finding.rule_id:
            return {
                "title": "New dependency added.",
                "summary": "This package now pulls in a dependency that was not present in the previous scan.",
                "why": "New dependencies can be normal, but they also expand the trust chain. A malicious update may hide the real payload in a newly added dependency.",
                "action": "Review the new dependency if the package also changed maintainer, source host, or install hooks.",
            }
        if finding.rule_id.startswith("HIST-") and finding.rule_id.endswith("-CHANGED"):
            return {
                "title": "Package build steps changed.",
                "summary": "The package build instructions changed since your last scan.",
                "why": "Build changes are common during updates, but malicious logic can also be inserted into build steps.",
                "action": "Review the changed build section if other warnings appeared in the same update.",
            }
        if finding.rule_id.startswith("HIST-") and finding.rule_id.endswith("-NEW-NETWORK"):
            return {
                "title": "New network fetch appeared in build steps.",
                "summary": "This package now appears to fetch data during a build-related function.",
                "why": "Network access during build steps can be legitimate, but it makes source provenance harder to review.",
                "action": "Review the changed function and use --deep-static for a closer source check.",
            }

        if finding.rule_id in DETERMINISTIC_TITLES:
            return self._deterministic_template(DETERMINISTIC_TITLES[finding.rule_id])
        return {}

    def _deterministic_template(self, title: str) -> Dict[str, str]:
        if "secret" in title.lower():
            return {
                "title": title,
                "summary": "This package references files or variables commonly used for private keys, tokens, or account credentials.",
                "why": "Packages should not normally read your SSH keys, GitHub tokens, browser profiles, or cloud credentials during build or installation.",
                "action": "Do not install unless you have manually reviewed and fully trust this behavior.",
            }
        return {
            "title": title,
            "summary": "AuraScan found a deterministic pattern that can be risky in package build or install logic.",
            "why": "This kind of behavior can be legitimate in rare cases, but it is powerful enough to deserve careful review.",
            "action": "Review the evidence before installing. Do not proceed if this behavior is unexpected.",
        }

    def _fallback_title(self, finding: Finding) -> str:
        if finding.severity == Severity.CRITICAL:
            return "Potentially blocking package behavior found."
        if finding.severity == Severity.HIGH:
            return "Potential high-risk package behavior found."
        if finding.severity == Severity.MEDIUM:
            return "Potential package behavior needs review."
        return "Package note may need review."

    def _fallback_summary(self, finding: Finding) -> str:
        if finding.severity in (Severity.HIGH, Severity.CRITICAL):
            summary = "AuraScan found behavior that may be risky and needs review."
        if finding.severity == Severity.MEDIUM:
            summary = "AuraScan found behavior that may matter for package trust."
        if finding.severity == Severity.LOW:
            summary = "AuraScan found a lower-risk note from one of its scanners."
        if finding.explanation and finding.rule_id not in finding.explanation:
            return f"{summary} Scanner note: {finding.explanation}"
        return summary

    def _fallback_why(self, finding: Finding) -> str:
        return "This finding came from one of AuraScan's scanners, but there is no specialized explanation template for this exact rule yet."

    def _fallback_action(self, finding: Finding) -> str:
        if finding.severity in (Severity.HIGH, Severity.CRITICAL):
            return "Review the evidence before installing. Use --verbose to see technical details."
        return "Review if this package is new to you or other warnings appear. Use --verbose to see technical details."

    def _has_specific_default_text(self, finding: Finding) -> bool:
        return bool(finding.user_title or self._template(finding))

    def _show_group_by_default(self, item: PresentedFinding) -> bool:
        if item.synthetic or item.severity in (Severity.HIGH, Severity.CRITICAL):
            return True
        for finding in item.findings:
            if finding.show_by_default and not (finding.severity == Severity.LOW and not self._has_specific_default_text(finding)):
                return True
        return False

    def _section_for(self, finding: Finding, severity: Severity) -> str:
        if finding.blocks_installation or severity == Severity.CRITICAL:
            return "Critical blockers"
        metadata = get_rule_metadata(finding.rule_id)
        category = metadata.category if metadata else ""
        if finding.rule_id.startswith("HIST-") or category == RuleCategory.history_supply_chain:
            return "Supply-chain history"
        if category in (RuleCategory.pgp_signature, RuleCategory.checksum_integrity) or "CHECKSUM" in finding.rule_id or "SIGNATURE" in finding.rule_id or "PGP" in finding.rule_id:
            return "Signatures and checksums"
        if finding.rule_id.startswith("SOURCE-META-") or category == RuleCategory.source_metadata:
            return "Source metadata"
        if finding.rule_id.startswith("CLAMAV-") or category == RuleCategory.clamav_signature:
            return "Malware signatures"
        if finding.source.value == "ai_review" or category == RuleCategory.ai_review:
            return "AI review"
        if finding.source.value == "deterministic_rule" or category in (
            RuleCategory.deterministic_static,
            RuleCategory.credential_exposure,
            RuleCategory.persistence,
            RuleCategory.network_behavior,
            RuleCategory.archive_safety,
            RuleCategory.source_acquisition,
        ):
            return "Static code findings"
        return "Other findings"
