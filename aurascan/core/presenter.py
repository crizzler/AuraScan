from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

from aurascan.core.models import Finding, Severity
from aurascan.core.rule_metadata import RuleCategory, get_display_group, get_display_priority, get_rule_metadata
from aurascan.core.text_safety import sanitize_terminal_text


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

EXACT_TEMPLATES: Dict[str, Dict[str, str]] = {
    'EDITOR-TASK-AUTORUN-CARRIER-001': {
        'title': 'An automatic editor task treats an asset path as code.',
        'summary': 'A captured folder-open task or its reachable dependency invokes an interpreter with a literal data, media, document or font path as code.',
        'why': 'Editor task configuration can introduce execution independently of package build functions when workspace trust and automatic-task permissions allow it.',
        'checked': 'AuraScan structurally parsed bounded captured task bytes and supported Linux command arguments without executing commands or opening their targets.',
        'not_prove': 'This does not prove the target exists, contains malware, belongs to a particular campaign, ran successfully, or compromised the host.',
        'action': 'Keep automatic tasks disabled for this workspace and review the task and referenced carrier as inert data before accepting this revision.',
    },
    'EDITOR-TASK-INSPECTION-INCOMPLETE-001': {
        'title': 'Editor task inspection did not complete.',
        'summary': 'Malformed task data, ambiguous dependencies, unsupported active command syntax or a resource bound prevented complete structural inspection.',
        'why': 'An unresolved automatic execution path cannot be treated as inspected.',
        'checked': 'AuraScan applied bounded static JSON and command-field parsing without resolving variables, invoking extensions or executing tasks.',
        'not_prove': 'Incomplete coverage is not evidence of malware, task execution or host compromise.',
        'action': 'Review the unresolved configuration as inert data before building; keep automatic tasks disabled while reviewing it.',
    },
    'SUPPLYCHAIN-NPM-SHAIHULUD-20260907': {
        'title': 'An observed malicious npm release is selected.',
        'summary': 'A supported package installation or decoded dependency field selects an exact package/version tuple reported in the September 2026 Shai-Hulud campaign.',
        'why': 'Package installation can invoke attacker-controlled lifecycle scripts. Registry availability or registry scanning cannot clear this match.',
        'checked': 'AuraScan compared captured control text or metadata with bundled, referenced campaign intelligence without installing dependencies.',
        'not_prove': 'Selection is not proof of installation, execution, successful propagation, or host compromise.',
        'action': 'Do not build this revision. If independent evidence confirms installation or execution, investigate from a clean environment and rotate exposed credentials from a separate clean machine.',
    },
    'DEEPSTATIC-NPM-SHAIHULUD-20260907': {
        'title': 'An observed malicious npm release is selected.',
        'summary': 'A supported package installation or decoded dependency field selects an exact package/version tuple reported in the September 2026 Shai-Hulud campaign.',
        'why': 'Package installation can invoke attacker-controlled lifecycle scripts. Registry availability or registry scanning cannot clear this match.',
        'checked': 'AuraScan compared captured control text or metadata with bundled, referenced campaign intelligence without installing dependencies.',
        'not_prove': 'Selection is not proof of installation, execution, successful propagation, or host compromise.',
        'action': 'Do not build this revision. If independent evidence confirms installation or execution, investigate from a clean environment and rotate exposed credentials from a separate clean machine.',
    },
    'SUPPLYCHAIN-NPM-SHAIHULUD-REVIEW-001': {
        'title': 'An npm malware-advisory package needs version review.',
        'summary': 'A package named in the malware advisories is selected, but the captured selector does not establish an exact observed campaign release.',
        'why': 'The broad advisories list no patched version. A different version, tag, or unresolved range is not evidence of safety.',
        'checked': 'AuraScan inspected captured package identities and selectors locally; it did not resolve a registry tag or install a dependency.',
        'not_prove': 'This finding does not establish which bytes dependency resolution would choose or that this host ran the package.',
        'action': 'Resolve the exact dependency provenance and malware-advisory scope in a clean environment before accepting the build.',
    },
    'DEEPSTATIC-NPM-SHAIHULUD-REVIEW-001': {
        'title': 'An npm malware-advisory package needs version review.',
        'summary': 'A package named in the malware advisories is selected, but the captured selector does not establish an exact observed campaign release.',
        'why': 'The broad advisories list no patched version. A different version, tag, or unresolved range is not evidence of safety.',
        'checked': 'AuraScan inspected captured package identities and selectors locally; it did not resolve a registry tag or install a dependency.',
        'not_prove': 'This finding does not establish which bytes dependency resolution would choose or that this host ran the package.',
        'action': 'Resolve the exact dependency provenance and malware-advisory scope in a clean environment before accepting the build.',
    },
    'DEEPSTATIC-NPM-SHAIHULUD-PAYLOAD-001': {
        'title': 'Captured source bytes match a known malicious payload.',
        'summary': 'A stable regular source file has the exact SHA-256 published for the Shai-Hulud npm payload.',
        'why': 'An exact known-malicious file hash remains adverse evidence regardless of its filename, dependency metadata, signature, or registry availability.',
        'checked': 'AuraScan hashed bounded no-follow source bytes; it did not execute, deobfuscate, or import the payload.',
        'not_prove': 'File presence alone does not prove it executed, persisted, propagated, or compromised this system.',
        'action': 'Do not build or execute this source. Preserve evidence and investigate any independently established installation or execution from a clean environment.',
    },
    'SUPPLYCHAIN-NPM-SHAIHULUD-C2-001': {
        'title': 'A static network target matches confirmed campaign infrastructure.',
        'summary': 'A supported active network command uses the exact known Shai-Hulud C2 hostname.',
        'why': 'Known malicious infrastructure is adverse evidence; a similar spelling or a hostname appearing only in a URL path is not this match.',
        'checked': 'AuraScan parsed the command destination locally without contacting that host.',
        'not_prove': 'This does not establish that a connection succeeded, data was transferred, or this host was compromised.',
        'action': 'Do not run this build. Review the control path and any independent execution evidence before deciding incident response.',
    },
    'DEEPSTATIC-NPM-SHAIHULUD-C2-001': {
        'title': 'A static network target matches confirmed campaign infrastructure.',
        'summary': 'A supported active network command uses the exact known Shai-Hulud C2 hostname.',
        'why': 'Known malicious infrastructure is adverse evidence; a similar spelling or a hostname appearing only in a URL path is not this match.',
        'checked': 'AuraScan parsed the command destination locally without contacting that host.',
        'not_prove': 'This does not establish that a connection succeeded, data was transferred, or this host was compromised.',
        'action': 'Do not run this build. Review the control path and any independent execution evidence before deciding incident response.',
    },
    'SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001': {
        'title': 'npm supply-chain inspection did not complete.',
        'summary': 'A required parser, entry script, intelligence record, or configured resource bound prevented complete inspection.',
        'why': 'Missing or ambiguous evidence cannot be treated as an inspected dependency chain.',
        'checked': 'AuraScan used bounded static parsing and captured local evidence without executing package code.',
        'not_prove': 'Incomplete coverage is not a malware finding or evidence of exploitation.',
        'action': 'Provide stable, supported inputs or review the unresolved scope in a disposable bounded environment before building.',
    },
    'NPM-LIFECYCLE-SUPPLYCHAIN-001': {
        'title': 'An install-time entry script has correlated supply-chain indicators.',
        'summary': 'A package lifecycle hook launches the captured package-root entry script, which targets known C2 or combines sensitive access with persistence and network or publication behavior.',
        'why': 'The correlation connects install-time code to multiple sensitive operations. A Bun or Node entry point alone does not establish this finding.',
        'checked': 'AuraScan inspected supported literal lifecycle commands and bounded lexical JavaScript evidence from the same captured package.',
        'not_prove': 'This static correlation does not prove the code ran, credentials were stolen, propagation succeeded, or the host is compromised.',
        'action': 'Do not build this revision until the entry script and dependency provenance have been independently reviewed.',
    },
    'NPM-LIFECYCLE-CREDENTIAL-ACCESS-001': {
        'title': 'An install-time entry script accesses credential-related data.',
        'summary': 'A captured lifecycle entry script contains supported credential file or environment access operations.',
        'why': 'Install-time credential access needs review because the dependency may run with the installer account permissions.',
        'checked': 'AuraScan distinguished access expressions from comments and documentation strings in bounded captured code.',
        'not_prove': 'The pattern does not prove the access succeeded, any secret existed, data left the system, or compromise occurred.',
        'action': 'Review why installation needs this access and remove unexpected dependency behavior before accepting the build.',
    },
    'NPM-LIFECYCLE-PERSISTENCE-001': {
        'title': 'An install-time script writes agent or editor configuration.',
        'summary': 'Captured lifecycle code writes a recognized agent/editor control path and contains additional sensitive behavior.',
        'why': 'Changes to these control files can affect later tool or agent execution; mere file presence is insufficient for this correlation.',
        'checked': 'AuraScan inspected supported write calls in the bound lifecycle entry script without opening the target configuration.',
        'not_prove': 'The match does not prove the write occurred or that the resulting configuration would execute code.',
        'action': 'Review the intended configuration writes and accompanying behavior before accepting the dependency.',
    },
    'NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001': {
        'title': 'npm supply-chain inspection did not complete.',
        'summary': 'A required parser, entry script, intelligence record, or configured resource bound prevented complete inspection.',
        'why': 'Missing or ambiguous evidence cannot be treated as an inspected dependency chain.',
        'checked': 'AuraScan used bounded static parsing and captured local evidence without executing package code.',
        'not_prove': 'Incomplete coverage is not a malware finding or evidence of exploitation.',
        'action': 'Provide stable, supported inputs or review the unresolved scope in a disposable bounded environment before building.',
    },
    "PNPM-VULNERABLE-BUILDCHAIN-001": {
        "title": "The local pnpm package is in an affected build-tool version range.",
        "summary": "Package control text requests pnpm dependency resolution and the local pacman record matches the affected upstream ranges for CVE-2026-82392 and CVE-2026-82393.",
        "why": "Hostile lockfile or dependency manifest names can redirect filesystem writes; --ignore-scripts does not prevent the manifest-name issue.",
        "checked": "AuraScan read bounded no-follow local package records and used trusted Arch version comparison without executing pnpm or contacting a registry.",
        "not_prove": "This does not prove malicious package contents, exploitation, or which executable a future PATH, Corepack, or project pin will select.",
        "action": "Use a verified patched build environment before processing untrusted dependencies. The upstream fixes are 10.34.5 and 11.11.0.",
    },
    "PNPM-BUILDCHAIN-CONTEXT-INCOMPLETE-001": {
        "title": "The pnpm build-tool context could not be established.",
        "summary": "Relevant package control text references pnpm, but its installed version or invocation cannot be established from bounded local evidence.",
        "why": "Missing, changing, unsafe, custom, or ambiguous toolchain evidence cannot authorize a dependency-processing handoff.",
        "checked": "AuraScan inspected static shell controls and, where applicable, the local pacman database. It did not execute pnpm.",
        "not_prove": "This is incomplete coverage, not proof of a vulnerable installation, malware, or exploitation.",
        "action": "Establish the intended patched pnpm environment and stable local package metadata, then repeat the scan.",
    },
    "PNPM-LOCKFILE-PATH-ESCAPE-001": {
        "title": "A pnpm lockfile package name contains unsafe path components.",
        "summary": "A decoded package-name field contains traversal or an absolute-path component.",
        "why": "Dependency tools can turn these metadata names into filesystem destinations outside their intended package directories.",
        "checked": "AuraScan inspected structural fields in bounded literal pnpm YAML without evaluating YAML objects, invoking pnpm, or contacting a registry.",
        "not_prove": "This is static metadata evidence. No dependency installation, file write, or code execution was observed.",
        "action": "Do not build this revision until the metadata and dependency provenance have been independently reviewed; disabling lifecycle scripts is insufficient.",
    },
    "NPM-MANIFEST-NAME-PATH-ESCAPE-001": {
        "title": "A package manifest name contains unsafe path components.",
        "summary": "The decoded package.json name contains traversal or an absolute-path component, independently of any lifecycle scripts.",
        "why": "A structurally ordinary dependency archive can still supply a name that a vulnerable package manager uses as an unsafe filesystem destination.",
        "checked": "AuraScan decoded bounded JSON and checked the name as both an npm identifier and a filesystem component. It did not execute package code.",
        "not_prove": "The finding does not establish that this manifest was consumed as a dependency, a vulnerable tool was used, files were written, or compromise occurred.",
        "action": "Do not build this revision until the manifest name and dependency provenance have been reviewed. --ignore-scripts does not prevent metadata-driven file writes.",
    },
    "NPM-METADATA-INSPECTION-INCOMPLETE-001": {
        "title": "Package metadata inspection did not complete.",
        "summary": "A package manifest, npm lockfile/shrinkwrap, or pnpm lockfile has malformed, ambiguous, unsupported, or over-limit metadata.",
        "why": "Accepting metadata after silently skipping unsupported fields could hide a path escape or an unresolved campaign dependency.",
        "checked": "AuraScan used strict bounded JSON or a literal pnpm YAML subset, rejecting duplicate keys, unsupported structure, and ambiguous dependency identities without running a package manager.",
        "not_prove": "Unsupported syntax or invalid names are missing coverage, not proof of malicious behavior or a vulnerable package manager.",
        "action": "Review the complete metadata in a trusted environment and provide supported, unambiguous inputs before building.",
    },
    "PYTHON-BYTECODE-PRESENT-001": {
        "title": "A precompiled Python carrier is present in package inputs.",
        "summary": "Inspection found a Python bytecode header or a .pyc, .pyo, or .pyd carrier candidate, including files without executable permission.",
        "why": "Reviewing nearby Python source does not establish the behavior of precompiled bytes. A .pyd file is a native-extension candidate, not a PEP 552 bytecode header.",
        "checked": "AuraScan captured bounded inert file evidence; filenames select candidates and recognized headers refine their classification.",
        "not_prove": "Presence alone does not prove executable content, malicious behavior, repository tracking, installation, or execution. Precompiled files may be legitimate.",
        "action": "Review the artifact provenance and intended build or import role before accepting the package.",
    },
    "PYTHON-BYTECODE-UNCHECKED-HASH-001": {
        "title": "A Python bytecode header disables source checking.",
        "summary": "A recognized CPython PEP 552 header declares hash-based invalidation with source checking disabled.",
        "why": "Under the default interpreter policy, this mode can use cached bytecode without validating it against nearby source.",
        "checked": "AuraScan interpreted only a recognized magic number and the complete 16-byte header. It never imported, unmarshaled, disassembled, or executed a code object.",
        "not_prove": "The header does not authenticate the body or prove valid bytecode, a source mismatch, malicious behavior, or execution. This mode also supports legitimate distribution workflows.",
        "action": "Establish the artifact provenance and expected runtime role before accepting it.",
    },
    "PYTHON-BYTECODE-EXEC-001": {
        "title": "Acquired shell text references a precompiled carrier for execution.",
        "summary": "A supported shell command supplies the exact path of a captured precompiled Python carrier as executable input.",
        "why": "The static reference connects opaque bytes to a possible execution path that nearby Python source cannot explain or authenticate.",
        "checked": "AuraScan correlated captured paths with bounded shell text; relative paths require a supported explicit working-directory binding.",
        "not_prove": "This does not prove the script ran, that the bytes form valid executable code, or that the carrier is malicious.",
        "action": "Do not build until the carrier provenance and its complete execution reference have been independently reviewed.",
    },
    "IG-INTEGRITY-WEAK-CONTROL-PERMISSIONS": {
        "title": "Agent control file has unsafe write permissions.",
        "summary": "The file is writable by a group or other account class, so AuraScan will not enroll its current hash as trusted.",
        "why": "Another account with write access could replace the instructions after review while the same path continues to look familiar.",
        "checked": "AuraScan inspected the file as bounded text and checked its ownership, mode, identity, and stable-read metadata without executing it.",
        "not_prove": "Broad write permission alone does not prove that the file changed, contains malicious instructions, or caused compromise.",
        "action": "Restrict the file to owner-controlled writes, verify its contents, and scan it again before enrollment.",
    },
    "IG-CONFIG-CURSOR-BROAD-GRANT": {
        "title": "Cursor settings request broad tool approval.",
        "summary": "A supported allowlist or Auto-review guidance requests approval-free access across a broad tool surface.",
        "why": "Repository-controlled approval settings can increase the authority available to poisoned project instructions.",
        "checked": "AuraScan inspected bounded structural permission fields without running Cursor or resolving effective policy.",
        "not_prove": "The grant alone does not establish maliciousness, actual approval, execution, or compromise; user and team policy and Cursor run mode still matter.",
        "action": "Review the exact approval scope against your intended project and user policy before approving the file's integrity baseline.",
    },
    "IG-CONFIG-CURSOR-COMMAND-BEHAVIOR": {
        "title": "Cursor command configuration contains sensitive behavior.",
        "summary": "Supported command fields correlate remote retrieval with execution or credential-file access with outbound transfer.",
        "why": "A configured command can cross a trust boundary if the server starts or a tool receives approval.",
        "checked": "AuraScan inspected literal command arguments and supported shell text as inert data; it did not start a server, resolve credentials or contact an endpoint.",
        "not_prove": "Static configuration does not establish activation, execution, successful transfer, campaign attribution, or compromise.",
        "action": "Review the command's purpose and provenance and resolve the reported behavior before approving the control file.",
    },
    "IG-CONFIG-CURSOR-AUTOREVIEW-BEHAVIOR": {
        "title": "Cursor Auto-review guidance contains sensitive behavior.",
        "summary": "Allow guidance contains a deterministic correlation of sensitive instruction behaviors.",
        "why": "Repository-controlled natural-language guidance can influence decisions about tool approval.",
        "checked": "AuraScan inspected the supported allow-instructions field independently of block guidance and descriptive metadata.",
        "not_prove": "This does not establish Cursor's effective policy, classifier behavior, tool approval, execution, or compromise.",
        "action": "Review the requested behavior and approval scope before approving the control file's integrity baseline.",
    },
    "IG-INTEGRITY-WEAK-PARENT-PERMISSIONS": {
        "title": "Agent control file has an unsafe parent directory chain.",
        "summary": "A parent directory is foreign-owned, broadly writable, or could not be revalidated as stable, so path-bound trust is unsafe.",
        "why": "A writable or unstable parent can allow a reviewed file path to be redirected or replaced after approval.",
        "checked": "AuraScan inspected the file bytes but separately validated every relevant parent directory before considering baseline enrollment.",
        "not_prove": "This directory condition is not evidence that the file is malicious, was replaced, or executed by an agent.",
        "action": "Correct the parent ownership or write permissions, verify the file and directory layout, and scan again.",
    },
    "IG-INTEGRITY-MULTIPLY-LINKED-CONTROL": {
        "title": "Agent control file has more than one filesystem name.",
        "summary": "The same inode is reachable through another hard-link path, so AuraScan will not enroll this path's hash as trusted.",
        "why": "Content changed through an unseen hard link would also change this agent control file without modifying its reviewed pathname.",
        "checked": "AuraScan inspected the stable file snapshot and verified that its filesystem link count is not one.",
        "not_prove": "Multiple hard links do not by themselves prove malicious content, tampering, agent execution, or compromise.",
        "action": "Replace the control file with a reviewed standalone regular file, then scan it again before enrollment.",
    },
    "IG-INTEGRITY-SYMLINK-MANUAL-TRUST": {
        "title": "Agent control file uses a symlink and needs manual review.",
        "summary": "The symlink stays inside the selected root and its regular-file target was inspected, but AuraScan will not enroll the linked path.",
        "why": "A symlink separates the discovered agent path from the object holding its content, making automatic path-and-hash trust less reliable.",
        "checked": "AuraScan resolved the file link without traversing symlink directories, confirmed that the target stayed inside the root, and analyzed a stable bounded snapshot.",
        "not_prove": "An inside-root symlink is not proof of malicious instructions, an outside-root escape, execution, or compromise.",
        "action": "Review the link and target manually; use a standalone regular control file if you want it to become eligible for enrollment.",
    },
    "HIST-MAINTAINER-ANNOTATION-CHANGED": {
        "title": "PKGBUILD maintainer annotation changed.",
        "summary": "The maintainer comment was added, removed, or edited since the accepted local scan.",
        "why": "Comment edits can be ordinary maintenance, but they deserve review alongside changes to package code or verification.",
        "checked": "AuraScan compared maintainer comment text in the current PKGBUILD and the accepted local snapshot.",
        "not_prove": "Comments do not establish AUR ownership, orphan status, restoration, adoption, or compromise.",
        "action": "Review the package changes. Confirm ownership separately from authoritative AUR metadata or history if it matters to the decision.",
    },
    "HIST-MAINTAINER-CHANGED": {
        "title": "Maintainer metadata needs review.",
        "summary": "An earlier local scan recorded changed maintainer text; AUR account ownership was not verified.",
        "why": "Legacy history findings used PKGBUILD comments, which do not establish an account transition.",
        "action": "Review the update more carefully if this change appears together with source URL changes, removed signatures, new dependencies, or new install hooks.",
    },
    "HIST-ORPHAN-ADOPTED": {
        "title": "Earlier adoption inference is unverified.",
        "summary": "An earlier local scan observed maintainer text appearing; missing text does not establish orphan status or adoption.",
        "why": "An AUR ownership transition requires authoritative package-bound before-and-after maintainer state.",
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
    "SUPPLYCHAIN-AUR-JS-20260611": {
        "title": "Package invokes a known June 2026 AUR campaign payload.",
        "summary": "The PKGBUILD or install hook attempts to install a JavaScript package name tied to the June 2026 malicious AUR adoption campaign.",
        "why": "The Arch AUR incident report identified these dependency names in malicious package changes. Executing the build or install hook could run attacker-controlled JavaScript.",
        "checked": "AuraScan matched the command and dependency name locally without executing package code or contacting the threat-intelligence source.",
        "not_prove": "The static match does not prove that the payload executed on this host, but it is strong enough to stop the build.",
        "action": "Do not build or install this revision. Preserve the AUR commit details and investigate any earlier installation from trusted media.",
    },
    "DEEPSTATIC-SUPPLYCHAIN-AUR-JS-20260611": {
        "title": "Downloaded source contains a known June 2026 AUR campaign payload.",
        "summary": "A safely acquired source file attempts to install a JavaScript dependency name tied to the June 2026 malicious AUR adoption campaign.",
        "why": "Source-side install commands can execute attacker-controlled package lifecycle scripts during a build.",
        "checked": "AuraScan inspected the acquired source as bounded text and did not execute it.",
        "not_prove": "This match does not prove execution on the host, but the source revision should not be trusted.",
        "action": "Do not build this source revision. Preserve its provenance and investigate any earlier build from trusted media.",
    },
    "SUPPLYCHAIN-AUR-HYPRLAND-FIXES-20260828": {
        "title": "Package uses the reported hyprland-fixes backdoor source.",
        "summary": "The PKGBUILD points to the source repository identified in the 28 August 2026 Arch AUR report.",
        "why": "That repository contains code which attempts Tailscale enrollment, persistent root SSH access, sudoers changes, and evidence erasure.",
        "checked": "AuraScan matched the declared source URL as static text and did not download or execute it.",
        "not_prove": "This match does not prove that the payload ran on this host, but the referenced revision must not be trusted.",
        "action": "Do not build or install this package. Preserve its package and commit metadata and investigate any earlier installation from trusted media.",
    },
    "SUPPLYCHAIN-AUR-REPO-PROPAGATION-001": {
        "title": "Package code may propagate changes into AUR repositories.",
        "summary": "The PKGBUILD or install hook combines an AUR Git remote, repository mutation or staging, and a non-dry-run Git push.",
        "why": "Package build and install code should not modify and publish other AUR repositories. This combination can spread attacker-controlled package changes through a maintainer's repositories.",
        "checked": "AuraScan correlated direct Git commands in package text without running them, contacting the AUR, or accessing SSH credentials.",
        "not_prove": "This static match does not prove that a push ran, succeeded, or changed any remote repository, but the propagation chain is unsafe enough to block the package.",
        "action": "Do not build or install this revision. Preserve the package metadata and review the full repository-modification logic from a trusted environment.",
    },
    "AUR-REPO-OPAQUE-ARTIFACT-001": {
        "title": "Opaque artifact is present beside the PKGBUILD.",
        "summary": "AuraScan found an executable-format or archive artifact that is not represented by the package's statically resolved source entries.",
        "why": "Bytes stored beside packaging metadata are harder to attribute to a reviewed upstream source and checksum, even when they are legitimate.",
        "checked": "AuraScan used a bounded, no-follow snapshot and file magic to compare the local artifact with the PKGBUILD's static source mapping.",
        "not_prove": "This does not prove the file is Git-committed, installed, executed, malicious, or part of a compromise.",
        "action": "Verify why the artifact is present and establish its source and expected digest before trusting the package checkout.",
    },
    "AUR-REPO-OPAQUE-BINARY-001": {
        "title": "Package logic can install an undeclared opaque artifact.",
        "summary": "Package logic requests a copy of an executable-format or archive artifact from beside the PKGBUILD into $pkgdir without a matching static source entry.",
        "why": "The packaged bytes can reach users without provenance being visible in the declared source and checksum metadata.",
        "checked": "AuraScan correlated the exact captured artifact path and identity with an active install, copy, or move command targeting $pkgdir.",
        "not_prove": "Static correlation does not prove the command ran, the artifact is malicious, or an installed program would execute successfully.",
        "action": "Review the artifact provenance, digest, licensing, and intended installed destination before approving this exact scan.",
    },
    "AUR-REPO-OPAQUE-BINARY-EXEC-001": {
        "title": "Package logic can execute an opaque artifact or request elevated file permissions.",
        "summary": "Package control logic can invoke the exact opaque artifact, invoke its installed destination from an install hook, or give that destination a set-user-ID or set-group-ID mode.",
        "why": "This connects hard-to-inspect bytes to active code execution or an elevated permission boundary.",
        "checked": "AuraScan correlated the exact observed artifact with an active control-text reference; installed destinations and declared hooks are included only when that specific chain is present.",
        "not_prove": "Static evidence does not prove a build or hook ran, execution succeeded, privileges changed, credentials were accessible, or compromise occurred.",
        "action": "Do not build or install this revision until the artifact and complete execution or permission chain have been independently reviewed.",
    },
    "AUR-REPO-INSPECTION-INCOMPLETE-001": {
        "title": "Package-repository provenance inspection did not complete.",
        "summary": "AuraScan could not obtain a bounded, stable, no-follow snapshot of the files beside the PKGBUILD.",
        "why": "Allowing a build after skipping an unreadable, replaced, oversized, linked, or unsupported entry could leave an opaque payload uninspected.",
        "checked": "AuraScan validated directory and file types, bounded traversal and reads, and rechecked identities after capture.",
        "not_prove": "Incomplete inspection is not evidence that the package or an omitted file is malicious.",
        "action": "Do not build until the package checkout can be captured completely as stable regular files within the documented limits.",
    },
    "SUPPLYCHAIN-REMOTE-STAGE-EXEC-001": {
        "title": "Package downloads content and then executes it.",
        "summary": "The PKGBUILD or install hook writes remote content to a local artifact and later executes that artifact or content derived from it.",
        "why": "A harmless-looking first stage can defer its real behavior to mutable content fetched during a build or privileged install hook.",
        "checked": "AuraScan correlated command-position fetch, bounded transformation, and execution paths as static shell text. It did not fetch, decode, or execute the content.",
        "not_prove": "The static chain does not prove a connection occurred, what bytes a server returned, or that execution succeeded. It is still unsafe enough to block automatic installation.",
        "action": "Do not build or install this revision until the complete remote-content integrity and execution chain has been reviewed from a trusted environment.",
    },
    "SUPPLYCHAIN-OPAQUE-CARRIER-EXEC-001": {
        "title": "Package executes code through an opaque carrier.",
        "summary": "The PKGBUILD or install hook decodes local content into a file and later executes that exact file, or invokes a media, document, or font-named file as code.",
        "why": "Executable content can be disguised as an ordinary picture, document, font, or encoded asset so a surface review sees only an apparently inert file.",
        "checked": "AuraScan correlated active decode, artifact, and execution commands as bounded text. It did not decode, render, import, or execute the carrier.",
        "not_prove": "The static chain does not establish what bytes the carrier contains, why it was named this way, or whether execution would succeed. The behavior is still unsafe enough to block automatically.",
        "action": "Do not build or install this revision until the complete carrier and every transformation and execution step have been independently reviewed.",
    },
    "STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001": {
        "title": "Remote-stage inspection did not complete.",
        "summary": "AuraScan could not finish its bounded correlation of downloaded artifacts and later execution in package text.",
        "why": "Treating a parser or resource limit as a clear result could let a padded or malformed loader hide beyond the inspected command set.",
        "checked": "AuraScan parsed package logic as inert text with fixed input and command limits and did not execute any command.",
        "not_prove": "Incomplete inspection is not evidence that a download or execution occurred; it means AuraScan cannot safely authorize this revision.",
        "action": "Do not build or install until the complete package logic can be inspected within the static-analysis bounds.",
    },
    "DEEPSTATIC-REMOTE-STAGE-EXEC-001": {
        "title": "Downloaded source contains a second-stage execution chain.",
        "summary": "A source file writes additional remote content to a local artifact and later executes that artifact or content derived from it.",
        "why": "A reviewed source archive can still act as a loader for mutable code that is absent from the declared, checksummed source set.",
        "checked": "AuraScan inspected bounded source text and correlated the fetch and execution paths without running the source or acquiring the second stage.",
        "not_prove": "The static chain does not prove a connection occurred, what bytes were returned, or that execution succeeded.",
        "action": "Do not build this source revision until the undeclared remote stage and its integrity controls have been independently reviewed.",
    },
    "DEEPSTATIC-OPAQUE-CARRIER-EXEC-001": {
        "title": "Downloaded source executes code through an opaque carrier.",
        "summary": "A source file decodes local content into a file and later executes that exact file, or invokes a media, document, or font-named file as code.",
        "why": "A source archive can disguise executable content as an ordinary asset so its filename and surrounding project appear harmless during review.",
        "checked": "AuraScan correlated the active carrier and execution commands in bounded source text. It did not decode, render, import, or execute the carrier.",
        "not_prove": "The static chain does not establish the carrier's bytes, intent, or whether execution would succeed, but this source revision should not be built automatically.",
        "action": "Do not build this source revision until the complete carrier and every transformation and execution step have been independently reviewed.",
    },
    "DEEPSTATIC-INSPECTION-INCOMPLETE-001": {
        "title": "Acquired-source inspection did not complete safely.",
        "summary": "AuraScan reached a source-tree entry or candidate-file bound, or could not bind a candidate to an unchanged regular-file read.",
        "why": "Allowing a build after only part of an acquired source tree was inspected would let relevant build or loader logic remain outside the static review.",
        "checked": "AuraScan enumerated and read source candidates with fixed entry, candidate, and file-size limits and without following symlinks or executing content.",
        "not_prove": "An incomplete inspection does not prove that the source is malicious; it means AuraScan cannot safely authorize this source revision.",
        "action": "Do not build or install until the complete source tree can be inspected within the configured bounds from a trusted environment.",
    },
    "DEEPSTATIC-NESTED-ARCHIVE-UNINSPECTED-001": {
        "title": "A nested source archive remains uninspected.",
        "summary": "An acquired source tree contains another archive that AuraScan did not recursively expand.",
        "why": "Build logic can unpack and execute files from nested archives, so scanning only the outer tree would leave part of the source outside static review.",
        "checked": "AuraScan identified the nested archive as inert source-tree content and did not extract or execute it.",
        "not_prove": "A nested archive is not evidence of malware; this blocker records incomplete inspection.",
        "action": "Inspect every nested archive independently with equivalent bounds before building or installing.",
    },
    "INSTALL-HOOK-UNINSPECTED-001": {
        "title": "Declared install hook could not be inspected safely.",
        "summary": "The PKGBUILD declares local install code, but AuraScan could not bind it to a bounded, unchanged regular file inside the package directory.",
        "why": "Package install hooks can run with package-manager privileges. Allowing a build while the declared hook is missing, ambiguous, unreadable, unsafe, or linked through a symlink would leave privileged code outside the static review.",
        "checked": "AuraScan parsed the literal install declaration and attempted a bounded no-follow read without sourcing the PKGBUILD or executing the hook.",
        "not_prove": "An inspection failure does not prove the package or hook is malicious; it means the scan is incomplete and cannot safely authorize the build.",
        "action": "Repair or fully materialize the package checkout, ensure the hook is a local regular file with no symlinked path component, and scan again.",
    },
    "PACKAGE-INSTALL-HOOK-UNINSPECTED-001": {
        "title": "Built package install hook could not be inspected safely.",
        "summary": "AuraScan could not obtain a bounded, stable text view of the package archive's install-time control file.",
        "why": "A built package install hook can run with package-manager privileges, so an incomplete archive inspection cannot authorize installation.",
        "checked": "AuraScan opened the package without following a symlink and asked the system archive reader for a bounded member listing and hook payload.",
        "not_prove": "The inspection failure does not prove the package is malicious; it means privileged install code may remain unreviewed.",
        "action": "Do not install this archive. Obtain a valid unchanged package and scan it again, or inspect its structure from a trusted environment.",
    },
    "EXEC-INSTALL-HOOK-SUDO-001": {
        "title": "Install hook launches a command through sudo.",
        "summary": "The package install hook invokes sudo even though pacman install hooks already execute with package-manager privileges.",
        "why": "This can immediately run a newly installed, insufficiently reviewed executable with root authority.",
        "checked": "AuraScan inspected the declared local install hook as text without running it.",
        "not_prove": "This does not by itself identify the invoked program as malware, but the privilege pattern is unsafe enough to block automatic installation.",
        "action": "Do not install the package until the hook and every executable it invokes have been fully reviewed.",
    },
    "PRIV-SUDOERS-DROPIN-001": {
        "title": "Package changes sudo policy.",
        "summary": "Package logic installs or references a file under /etc/sudoers or /etc/sudoers.d.",
        "why": "Sudo policy can grant commands elevated authority after installation.",
        "checked": "AuraScan inspected package and install-hook text without applying the policy.",
        "not_prove": "Some administrative packages legitimately ship narrowly scoped sudo rules, so this path alone requires review rather than proving malware.",
        "action": "Review the complete sudoers file and every authorized command before installing.",
    },
    "PRIV-SUDOERS-NOPASSWD-001": {
        "title": "Package grants passwordless sudo execution.",
        "summary": "Package logic contains a NOPASSWD sudoers rule.",
        "why": "The named command can run with elevated authority without a fresh password prompt and may become a persistence path.",
        "checked": "AuraScan matched the sudoers directive as static text and did not install it.",
        "not_prove": "The match does not mean all commands receive passwordless sudo, but the exact grant is powerful enough to block automatic installation.",
        "action": "Do not install the package until the complete policy and authorized executable are independently reviewed.",
    },
    "REMOTE-ADMIN-BACKDOOR-001": {
        "title": "Package contains a correlated root remote-access chain.",
        "summary": "AuraScan found a remote-access anchor together with independent privilege, persistence, or anti-forensics behavior.",
        "why": "This combination can enroll a machine into an external network and preserve privileged remote shell access while hiding evidence.",
        "checked": "AuraScan correlated secret-free behavior labels from package text without executing commands or reporting embedded keys.",
        "not_prove": "The static match proves the dangerous instructions are present, not that enrollment or attacker access succeeded on this host.",
        "action": "Do not build or install this revision. Investigate any prior installation from trusted recovery media.",
    },
    "DEEPSTATIC-REMOTE-ADMIN-BACKDOOR-001": {
        "title": "Downloaded source contains a correlated root remote-access chain.",
        "summary": "A safely acquired source file combines remote-access behavior with independent privilege, persistence, or anti-forensics behavior.",
        "why": "Source-side commands can execute during package build, installation, or later helper execution with elevated authority.",
        "checked": "AuraScan inspected bounded source text without executing it and reports only secret-free behavior labels.",
        "not_prove": "The source match does not prove that the backdoor successfully ran or connected on this host.",
        "action": "Do not build this source revision. Preserve its provenance and investigate any earlier use from trusted recovery media.",
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
    "SOURCE-OFFLINE-UNINSPECTED": {
        "title": "Offline mode left a remote source uninspected.",
        "summary": "AuraScan made no network request, so it could not inspect one declared remote source.",
        "why": "A deep-static result is incomplete when any declared source content was unavailable for analysis.",
        "checked": "AuraScan classified the source declaration and enforced offline mode before any HTTP or Git acquisition call.",
        "not_prove": "This does not mean the source is malicious; it means AuraScan cannot call this deep-static scan complete.",
        "action": "Inspect a trusted local copy or rerun explicit deep-static acquisition with network access before installing.",
    },
    "SOURCE-LOCAL-UNSAFE": {
        "title": "A local source could not be captured safely.",
        "summary": "AuraScan refused a local source that escaped the package directory, used a link or special file, exceeded its bound, or changed while being copied.",
        "why": "Following unsafe paths or scanning unstable bytes could expose unrelated files or produce a misleading source result.",
        "checked": "AuraScan used bounded no-follow file-descriptor reads and required an unchanged regular file beneath the package directory.",
        "not_prove": "This does not prove malicious intent; it means the declared local source was not safely inspectable.",
        "action": "Use a complete package checkout containing ordinary local source files, then scan again before installing.",
    },
    "SOURCE-UNINSPECTED": {
        "title": "Deep source inspection is incomplete.",
        "summary": "At least one declared source did not become inspectable content during this deep-static run.",
        "why": "A clear deep-static result must cover every declared source rather than silently skipping one.",
        "checked": "AuraScan tracked each declared source acquisition independently.",
        "not_prove": "This does not prove the package is malicious; it records missing inspection evidence.",
        "action": "Do not install until every declared source can be acquired and inspected safely.",
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
    "ARCHIVE-INPUT-UNSAFE": {
        "title": "Archive input could not be captured safely.",
        "summary": "AuraScan refused an archive that was linked, non-regular, oversized, unavailable, or changing during capture.",
        "why": "Scanning bytes that differ from the bytes later extracted can create a false clear result.",
        "checked": "AuraScan captured the archive with bounded no-follow reads and verified its identity and digest around inspection.",
        "not_prove": "This does not prove malicious intent; it means AuraScan could not bind the result to stable archive bytes.",
        "action": "Use an unchanged regular archive from a trusted package checkout and scan it again before installing.",
    },
    "ARCHIVE-EXTRACTION-FAILED": {
        "title": "Archive extraction was incomplete.",
        "summary": "AuraScan stopped and removed its temporary output because the archive could not be extracted safely and completely.",
        "why": "A partial source tree can hide behavior in entries that were never reached or fully copied.",
        "checked": "AuraScan extracted into private staging and required consistent member sizes and an unchanged input snapshot.",
        "not_prove": "This does not prove the archive is malicious; it records incomplete static inspection.",
        "action": "Do not install until the complete archive can be inspected independently.",
    },
    "ARCHIVE-SPECIAL-FILE": {
        "title": "Archive contains a special entry type.",
        "summary": "AuraScan found a device, FIFO, or other unsupported non-regular archive member.",
        "why": "Materializing special entries is unsafe and skipping them would leave the archive only partially inspected.",
        "checked": "AuraScan classified archive members before transactional extraction.",
        "not_prove": "This does not prove compromise; it means the archive cannot be treated as a fully inspected ordinary source tree.",
        "action": "Inspect the archive provenance and contents independently; do not extract it automatically.",
    },
    "ARCHIVE-LINK-UNINSPECTED": {
        "title": "Archive link behavior was not fully inspected.",
        "summary": "AuraScan found an internal symbolic or hard link that its safe extractor deliberately did not materialize.",
        "why": "Silently skipping a link can hide which content a build accesses through that linked path.",
        "checked": "AuraScan validated the link metadata and refused to call the resulting partial tree a complete inspection.",
        "not_prove": "This does not prove the link is malicious; it records a deliberate static-analysis limitation.",
        "action": "Inspect the link target and build-time use independently before installing.",
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
        "summary": "AuraScan found a Git source selecting a movable tag rather than a full commit hash.",
        "why": "Tags can move; AuraScan has not verified tag protection or signatures.",
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
        or rule_id.startswith("UPG-")
        or rule_id in EXACT_TEMPLATES
        or rule_id in DETERMINISTIC_TITLES
        or (rule_id.endswith("-ADDED") and "DEPENDS" in rule_id)
        or (rule_id.startswith("HIST-") and rule_id.endswith("-CHANGED"))
        or (rule_id.startswith("HIST-") and rule_id.endswith("-NEW-NETWORK"))
    )


def known_presenter_template_rules() -> List[str]:
    return sorted(set(EXACT_TEMPLATES) | set(DETERMINISTIC_TITLES) | {"CLAMAV-*", "AI-*", "UPG-*", "HIST-*-CHANGED", "HIST-*-NEW-NETWORK", "HIST-*DEPENDS*-ADDED"})


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
            lines.append(sanitize_terminal_text(group.title))
            if group.summary:
                lines.append(sanitize_terminal_text(group.summary))
            if group.why_it_matters:
                lines.append("Why it matters: " + sanitize_terminal_text(group.why_it_matters))
            if group.checked:
                lines.append("What AuraScan checked: " + sanitize_terminal_text(group.checked))
            if group.not_prove:
                lines.append("What AuraScan did not prove: " + sanitize_terminal_text(group.not_prove))
            if group.recommended_action:
                lines.append("Recommended action: " + sanitize_terminal_text(group.recommended_action))
            if verbose:
                lines.append("Technical details:")
                for finding in group.findings:
                    detail = self._technical_detail(finding)
                    lines.append(
                        "- "
                        + sanitize_terminal_text(finding.rule_id, max_chars=256)
                        + f" ({finding.severity.value}): "
                        + sanitize_terminal_text(detail)
                    )

        if hidden and not verbose:
            note = "lower-risk note hidden" if len(hidden) == 1 else "lower-risk notes hidden"
            lines.append("")
            lines.append(f"{len(hidden)} {note}. Use --verbose to show them.")

        return lines, len(hidden)

    def _technical_detail(self, finding: Finding) -> str:
        detail = finding.technical_details or finding.evidence_snippet or finding.file_path
        if not finding.rule_id.startswith("AUR-REPO-"):
            return detail

        location = finding.file_path
        if finding.line_number is not None:
            location += ":" + str(finding.line_number)
        parts = []
        if location:
            parts.append("location " + location)
        if finding.file_hash:
            parts.append("artifact sha256 " + finding.file_hash[:12])
        if detail:
            parts.append(detail)
        return "; ".join(parts)

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
            {"HIST-MAINTAINER-ANNOTATION-CHANGED", "HIST-SOURCE-HOST-CHANGED"},
            {"HIST-MAINTAINER-ANNOTATION-CHANGED", "HIST-SOURCE-URL-CHANGED"},
            {"HIST-MAINTAINER-ANNOTATION-CHANGED", "HIST-PGP-REMOVED"},
            {"HIST-MAINTAINER-ANNOTATION-CHANGED", "HIST-INSTALL-ADDED"},
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
        matched = matched or (dependency_added and bool({"HIST-MAINTAINER-CHANGED", "HIST-MAINTAINER-ANNOTATION-CHANGED"} & rule_ids))
        matched = matched or "HIST-COMBINED-SUSPICIOUS-CHANGE" in rule_ids
        if not matched:
            return None

        severity = Severity.HIGH if any(f.severity == Severity.HIGH for f in history) else Severity.MEDIUM
        return PresentedFinding(
            title="Package update has multiple supply-chain risk signals.",
            summary="This update changed more than one trust-related part of the package, such as maintainer annotations, source location, dependencies, or verification settings.",
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
        if finding.rule_id in {"CLAMAV-TIMEOUT", "CLAMAV-INCOMPLETE"}:
            return {
                "title": "ClamAV inspection did not complete safely.",
                "summary": "The trusted ClamAV process could not finish within AuraScan's time and output limits.",
                "why": "An incomplete malware-signature scan is not evidence that a file is clean or malicious.",
                "action": "Do not install until the file can be scanned completely or inspected independently.",
            }
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
