# AuraScan

[![AUR package](https://img.shields.io/aur/version/aurascan?label=AUR&logo=archlinux)](https://aur.archlinux.org/packages/aurascan)

AI-assisted package safety for Arch-family Linux systems, pacman, AUR,
PKGBUILD, makepkg, and upgrade workflows.

AuraScan is a security-focused package scanner, upgrade preflight assistant,
and guarded incident recovery tool
for Arch Linux, EndeavourOS, Manjaro, CachyOS, and AUR workflows. It is
designed to catch obvious and moderately sophisticated malicious package
behavior, explain risky package metadata clearly, and reduce breakage risk
before routine upgrades. It can also inspect bounded crash evidence and prepare
verified repair recipes without allowing AI to invent shell commands. Optional
Assisted Background Recovery keeps networked AI analysis unprivileged and
separate from the offline deterministic repair service.
Foreground upgrade, incident, maintenance, and config-drift results can also
open a bounded contextual AI follow-up without granting AI command authority.
An optional foreground Repair Agent can separately grant arbitrary user-shell
or unrestricted root-shell command authority after explicit configuration and
live terminal consent. Root-shell mode is user-authorized remote code execution,
not a safety guarantee.
The optional AuraScan Recovery boot environment extends those guarded workflows
to an installed OS that cannot boot normally, with deterministic offline
diagnostics and separately consented provider AI.
The opt-in Agent Instruction Guard adds a bounded, unprivileged review layer
for AI-agent control files in a user's home directory without executing their
contents.

AuraScan does not prove that a package is safe. A clean report, a clean ClamAV
result, or a valid source signature is not a guarantee. The goal is to find risk
signals early, explain them clearly, and stop dangerous flows before package
code runs.

A clean ClamAV result is not proof of safety. A valid source signature is not a
guarantee that the package behavior is safe.

## Status

AuraScan is a developer preview. It is ready for early testing and review, but
its packaging, rule set, and integration story should still be treated as
pre-1.0.

## What You Can Try Now

AuraScan currently provides ten practical entry points:

- `aurascan --pkgbuild ./PKGBUILD` reviews package build metadata before trust.
- `aurascan-makepkg` scans before handing control to `makepkg`.
- `aurascan upgrade --dry-run` previews an Arch-family upgrade and reports
  pacman, AUR helper, known campaign, kernel/module, config drift, and AI-raised
  risks.
- `aurascan security-audit` checks installed packages and pacman history against
  validated AUR campaign intelligence, plus optional official Arch advisories.
- `aurascan instruction-audit` reviews recognized Claude Code, `AGENTS.md`, and
  Agent Skill control files for suspicious content and unexpected changes.
- `aurascan config-drift --dry-run` explains `.pacnew` and `.pacsave` files and
  prepares safe fixes with backups.
- `aurascan incidents --dry-run` diagnoses system and application crashes from
  bounded local logs without applying repairs.
- `aurascan recovery --status` manages an optional local recovery boot image;
  plain `aurascan recovery` inside that image starts the guided recovery UI.
- `aurascan ask --latest` reopens the newest private AuraScan result for
  bounded explanatory questions and locally verified follow-up actions.
- `aurascan agent --latest` opens the optional foreground Repair Agent. Its
  default `guarded` mode has no arbitrary command authority.

## Quickstart

AuraScan is published as [`aurascan`](https://aur.archlinux.org/packages/aurascan)
on the Arch User Repository. Review the `PKGBUILD`, then install it with an AUR
helper:

```bash
paru -S aurascan
# or
yay -S aurascan
```

To build directly from the AUR Git repository:

```bash
git clone https://aur.archlinux.org/aurascan.git
cd aurascan
makepkg -si
```

After installation, launch the setup wizard and verify the system integration:

```bash
aurascan init
aurascan doctor
```

For a development checkout:

```bash
git clone https://github.com/crizzler/AuraScan.git
cd AuraScan
python -m pip install -e ".[test]"
python -m aurascan init
python -m aurascan doctor
```

Release notes and recovery-image artifacts are available from the
[GitHub releases page](https://github.com/crizzler/AuraScan/releases).

Installation does not auto-run the wizard, collect API keys, write user config,
enable monitoring or repair services, install tray autostart, or add a recovery
boot entry as a side effect. Setup starts only when you run `aurascan init` or
`python -m aurascan init`.

## Why AuraScan Is Useful For Arch Users

AUR packages can run build scripts. Maintainer/package takeovers, source URL
changes, dependency tricks, weakened checksums, install hooks, and background
persistence patterns are real risks. Reading every PKGBUILD manually is easy to
forget, especially during routine updates.

AuraScan adds a fast automated safety layer before build or install steps. It
is not a replacement for judgment, but it reduces blind spots and gives risky
package behavior a clear review path.

For routine system maintenance, `aurascan upgrade` is meant to feel like a
native upgrade front door: it previews the pending transaction, checks common
Arch-family pitfalls, optionally asks AI to raise correlated risks, and then
hands off to pacman, paru, yay, or Shelly.

## Installation

AuraScan is available from the AUR as
[`aurascan`](https://aur.archlinux.org/packages/aurascan). It is not currently
part of Arch Linux's official binary repositories. The AUR recipe builds the
versioned GitHub source release, verifies fixed source checksums, and applies
any explicitly listed packaging patches before running the test suite.

Install with an AUR helper:

```bash
paru -S aurascan
# or
yay -S aurascan
```

The public package recipe and history can be reviewed independently:

```text
https://aur.archlinux.org/cgit/aur.git/tree/PKGBUILD?h=aurascan
```

For development:

```bash
python -m pip install -e ".[test]"
```

This installs the `aurascan` and `aurascan-makepkg` console scripts into the
active environment. It does not install pacman hooks and does not run the
wizard.

The Arch/AUR packaging recipe installs `/usr/bin/aurascan`,
`/usr/bin/aurascan-makepkg`, the pacman hook template, the optional updater
desktop/icon assets, disabled-by-default incident and Agent Instruction Guard
monitors and user assistants, Safe Autopilot services, recovery image profiles,
and a disabled recovery refresh hook. It does not build a UKI, alter an ESP, or
add a boot entry during package installation. It also installs a
non-interactive post-install message that points users to `aurascan init` and
`aurascan doctor`.

The source-tree reference recipe remains under `packaging/arch/`. The AUR Git
repository is the canonical public package history used by AUR clients.

## Compatibility

AuraScan targets Arch-family systems where pacman is the system package
manager. Core package scanning, `aurascan doctor`, `aurascan config-drift`,
`aurascan incidents`, and `aurascan upgrade --dry-run` are CLI-first and work
independently of the desktop environment.

| Distribution | Support tier | Notes |
| --- | --- | --- |
| Arch Linux | Supported | Generic pacman behavior with optional `paru` or `yay` AUR context. |
| EndeavourOS | Supported | Arch-compatible flow; `yay` is commonly available but not required. |
| CachyOS | Supported | Includes Shelly handoff support and CachyOS kernel/module checks when CachyOS packages are present. |
| Manjaro | Supported with caveats | Manjaro's delayed repositories can make AUR and mirror timing differ from Arch. Avoid partial upgrades and follow Manjaro's normal branch/update guidance. |
| Unknown Arch-like | Best effort | AuraScan uses conservative pacman behavior and Doctor reports what it can prove locally. |

Desktop support is intentionally layered:

- KDE Plasma on Wayland or X11 is the best-supported target for the optional
  AuraScan Updater tray icon.
- XFCE, Cinnamon, MATE, LXQt, and Budgie are expected to work when their normal
  tray/status-notifier support is enabled.
- GNOME is fully supported for CLI workflows, but the tray icon may require an
  AppIndicator/status-notifier extension.
- Tiling window managers can use AuraScan normally from the terminal; the tray
  applet needs a tray host such as the one provided by your panel/bar setup.

## What It Checks

The default scan is conservative and fast. It inspects package metadata,
PKGBUILD text, declared local install hooks when available, local history, and
available package archives. It can use deterministic rules, ClamAV when
available, source metadata checks, local history diffing, and structured risk
summaries. The separate security audit also checks a validated historical AUR
campaign snapshot, the reported August 2026 `hyprland-fixes` incident, bounded
pacman history, correlated host artifacts, and optional `arch-audit` advisories.

Default scans do not download declared sources, clone upstream repositories,
fetch PGP keys, run GPG, run makepkg, install packages, or execute package code.
The default scan context is `unknown`, which keeps update fast paths disabled.

The separate Agent Instruction Guard performs bounded, static content and
integrity checks on recognized AI-agent control files. It never imports,
renders, sources, or executes a discovered file. It is disabled until the user
opts in.

Deep static source inspection is opt-in: --deep-static is explicit. It safely acquires and inspects declared source
archives without executing package code. In this mode AuraScan may verify
detached signatures in an isolated temporary GPG home. Automatic key lookup is
limited to explicit source acquisition/deep-static flows and can be disabled
with `--no-auto-key-fetch` or `--offline`.

## What It Does Not Protect Against

AuraScan is not a sandbox, VM, or general process-behavior monitor. It does not
make makepkg safe after it starts running package functions. The Agent
Instruction Guard is a periodic control-file scanner, not synchronous
interception: it cannot stop a process that reads or changes a file between
scans. It does not preflight pasted commands or download links, use privileged
fanotify interception, or automatically quarantine files. AuraScan does not
guarantee malware detection, and it cannot see behavior hidden in files it did
not fetch or inspect.

ClamAV integration is useful when available, but a clean ClamAV scan is not
proof of safety. PGP signatures help confirm source integrity and signer
identity, but a valid signature does not prove that upstream code is safe or
that packaging behavior is harmless.

## Basic Usage

First-run setup:

```bash
aurascan init
aurascan doctor
aurascan doctor --check-ai
python -m aurascan init
python -m aurascan doctor
```

`aurascan init` can configure a cloud or local AI provider in
`~/.config/aurascan/.env`. Required cloud API keys are prompted with hidden
input; optional local-server tokens can be added as
`AURASCAN_LOCAL_AI_API_KEY`. The user config file is written with restrictive
permissions. The wizard recognizes the release-safe hook installed by the Arch
package and does not ask for a redundant local override. Source or development
installs can still repair a local hook at
`/etc/pacman.d/hooks/aurascan.hook` when needed.

LM Studio and `llama-server` expose compatible local APIs, so they can be
selected without installing another Python client:

```bash
aurascan init --provider lmstudio --model MODEL --enable-ai
aurascan init --provider llamacpp --model aurascan-local --enable-ai
aurascan init --provider llamacpp --model MODEL --base-url http://127.0.0.1:9000/v1 --enable-ai
aurascan doctor
aurascan doctor --check-ai
```

The presets use `http://127.0.0.1:1234/v1` for LM Studio and
`http://127.0.0.1:8080/v1` for llama.cpp. Start and load a model in the selected
server first; AuraScan does not start, download, or manage local models. The
wizard prompts for the model ID when `--model` is omitted. For llama.cpp,
`llama-server --alias aurascan-local ...` provides a stable ID instead of
exposing the model-file path as the default ID. See the official
[LM Studio OpenAI-compatible API documentation](https://lmstudio.ai/docs/developer/openai-compat)
and [llama-server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).

Local providers require explicit `AURASCAN_AI_ENABLED=1`, but do not require a
placeholder API key when their server has authentication disabled. Set
`AURASCAN_LOCAL_AI_API_KEY` when the local server requires a Bearer token, and
use `AURASCAN_AI_BASE_URL` to override a preset with another loopback HTTP(S)
endpoint. Local-provider URLs are restricted to loopback; AuraScan bypasses
environment proxies, refuses redirects, and never falls back to a cloud
provider. `aurascan doctor` remains offline unless `--check-ai` is supplied.

`aurascan init` can also configure upgrade preflight defaults. Upgrade
preflight is enabled by default even without an explicit setting, but the
wizard can record your preferred default helper, AI-review behavior, and config
drift assistant policy:

```bash
aurascan init --enable-upgrade-preflight --upgrade-aur-helper auto --enable-upgrade-ai
aurascan init --enable-config-drift --config-drift-ai-diffs ask
aurascan init --enable-updater-tray --install-updater-autostart
aurascan init --enable-incident-monitor --enable-incident-ai --incident-ai-evidence redacted
aurascan init --enable-incident-background-ai --incident-auto-repair safe
aurascan init --enable-instruction-monitor --disable-instruction-ai --instruction-scan-mode agent-surfaces
aurascan init --install-recovery --enable-recovery-ai --enable-recovery-auto-refresh --recovery-wifi-profiles ask
aurascan init --disable-upgrade-preflight
```

AI analysis is explicit in wizard-created configs. If you leave AI disabled,
AuraScan writes `AURASCAN_AI_ENABLED=0` and keeps normal scans deterministic and
local. `aurascan doctor` checks the selected provider, required credential
state, optional tools, hook status, and config permissions. It does not contact
the provider unless `--check-ai` is supplied. Selecting LM Studio or llama.cpp
keeps the request on the configured loopback server; it does not implicitly
authorize cloud AI.

When AuraScan is launched by a root pacman hook through `sudo`, it also checks
the invoking user's `~/.config/aurascan/.env` when `SUDO_USER` is available.
For root shells, unattended system updates, or hook contexts without an
invoking user, put system-wide AI settings in `/etc/aurascan/.env`.

Scan a PKGBUILD:

```bash
aurascan --pkgbuild ./PKGBUILD
```

Scan a built package archive:

```bash
aurascan --pkg /var/cache/pacman/pkg/example-1.0-1-x86_64.pkg.tar.zst
```

Emit JSON:

```bash
aurascan --json --pkgbuild ./PKGBUILD
```

Run explicit source acquisition and deep static inspection:

```bash
aurascan --deep-static --pkgbuild ./PKGBUILD
aurascan --deep-static --offline --no-auto-key-fetch --pkgbuild ./PKGBUILD
```

## Security Audit

`aurascan security-audit` correlates installed package names and bounded pacman
history with packaged AUR campaign intelligence. AuraScan ships a validated
snapshot of the community-maintained June 2026 incident list and labels its
provenance clearly. It parses package names as data and never executes the
upstream shell script. It also includes bounded intelligence for the 28 August
2026 [`hyprland-fixes` report](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/message/TAASU6LTO76UCKYLMG25OJPUY7ZONASN/).

```bash
aurascan security-audit
aurascan security-audit --verbose
aurascan security-audit --json
aurascan security-audit --refresh
aurascan security-audit --offline
```

`--refresh` downloads only the bounded HTTPS plain-text list, validates every
package name, hashes it, and stores it in private user state. A failed refresh
keeps the last validated packaged or cached list. Do not substitute a
`curl | bash` workflow.

When the optional `arch-audit` command is installed, AuraScan also imports its
strict JSON output. Those findings are shown separately because `arch-audit`
uses official Arch Security Team advisories for repository packages; it is not
an AUR-malware list. During `aurascan upgrade`, known campaign checks run by
default and official HIGH/CRITICAL advisories are raised only when the pending
repository transaction does not already include the affected package.

A package-name-only match is MEDIUM because cleaned packages can later be
legitimate. A matching pacman transaction inside the campaign window,
including a later removal, is CRITICAL exposure evidence, but still not proof
that the exact malicious commit executed. AuraScan does not automatically
remove packages or claim to clean a potentially compromised host.

For `hyprland-fixes`, an installed or pending name is HIGH, a helper-cache-only
match is LOW, and any matching install/update event in bounded pacman history
is CRITICAL; a removal event is also exposure evidence because uninstalling
does not undo host changes. The malicious repository history predates the
public report. The host audit also checks bounded, non-executing evidence at the
reported paths: disguised root-`sshd` configuration under
`/etc/pacman.d`, related systemd units and hourly persistence, the narrow
sudoers grant, duplicate SSH-key placement, payload copies, and the reported
firewall peer. One exact path is HIGH; multiple artifacts or validated behavior
markers are CRITICAL. Evidence labels omit auth-key and SSH-key material.

AuraScan intentionally does not alert on `tailscaled`, a Tailscale interface,
or a `100.64.0.0/10` address alone. Those are common legitimate conditions and
do not identify an attacker-controlled tailnet. Static source detection instead
correlates authenticated Tailscale SSH enrollment or hidden root-SSH behavior
with independent persistence, privilege, or anti-forensics signals. A match
proves suspicious code or artifacts were found, not that enrollment or remote
access succeeded.

## Agent Instruction Guard

AI-agent control files can influence an assistant every time a project or
skill is loaded. A poisoned file restored onto a rebuilt machine can therefore
reintroduce dangerous instructions while still looking like ordinary project
documentation. `aurascan instruction-audit` provides an opt-in, unprivileged
review workflow for this risk:

```bash
aurascan instruction-audit
aurascan instruction-audit --all-markdown --no-ai
aurascan instruction-audit --ai --json
aurascan instruction-audit --review
aurascan instruction-audit --review REPORT_ID
aurascan instruction-audit --approve FILE_ID
aurascan instruction-audit --disable FILE_ID
aurascan instruction-audit --restore ACTION_ID
aurascan instruction-audit --status
aurascan instruction-audit --enable-monitor
aurascan instruction-audit --enable-ai
aurascan instruction-audit --disable-monitor
aurascan instruction-audit --disable-ai
```

By default AuraScan scans recognized control surfaces under `$HOME`, including
`AGENTS.md`, `AGENTS.override.md`, `SKILL.md`, `CLAUDE.md`,
`CLAUDE.local.md`, and Claude rules, commands, agents, skills, memory, settings,
hooks, MCP/plugin manifests, and text scripts or resources belonging to a
discovered skill. `--root PATH` selects an explicit root for testing or a
deliberate one-shot scan. `--all-markdown` extends content analysis to other
Markdown files, but those extra files are not added to the integrity baseline.
`--no-ai` guarantees deterministic-only analysis; one-shot `--ai` requests the
separately configured provider without enabling the background AI timer. A
complete clear scan exits 0, a completed scan requiring review exits 1, and a
configuration or scan failure exits 2. Background capture records findings and
exits 0 so systemd does not mislabel detection as a failed service.

Discovery follows explicit Markdown imports and file symlinks only when the
final regular-file target stays inside an allowed root. It never traverses a
symlinked directory. Cache, trash, dependency, virtual-environment, and VCS
trees are pruned; directory, entry, candidate, size, and time limits keep each
run bounded, with continuation state for a large home. Files are opened without
following a final symlink unexpectedly, checked before and after the bounded
read, and treated only as inert text.

Deterministic rules correlate behaviors such as fetch plus execution,
credential access plus archive or upload, automatic activation plus
concealment, persistence plus dangerous actions, decode plus evaluation, and
privilege or sudo-policy abuse. The parser distinguishes active constructs from
quoted examples, fenced code, comments, negation, frontmatter, and invalid
configuration where possible. A match reports suspicious static instructions;
it does not prove that an assistant obeyed them or that credentials left the
machine.

Terminal review separates suspicious content from integrity-only review and
lists suspicious files first. Each content finding includes deterministic,
one-based line ranges from the bounded source file, semantic behavior labels,
and a fixed explanation of why the correlation needs review. It does not print
the source lines themselves. File-level integrity or parser findings say when
no precise line is available rather than inventing a location. When bounded
discovery is incomplete, the review identifies the displayed files as the
current page and explains that a saved continuation still needs to complete.

Content risk and integrity trust remain separate. Suspicious first-seen files
alert immediately; otherwise clean first-seen files enter one unreviewed
inventory. Their review state means that AuraScan has no machine-bound approval
for the content; it does not mean that a suspicious pattern was found. AI
analysis remains `not-needed` for a clean first-seen file with no deterministic
content finding. Approval records the exact hash and is bound to the local
machine identity and UID, so restoring an old manifest onto a rebuilt machine
does not silently establish trust. Reports, manifests, queued AI jobs, alert
state, and disable receipts use private permissions under
`$XDG_STATE_HOME/aurascan/instruction-guard/`. Version 0.9.0 introduces the
`instruction_guard_report/1.0` schema and Instruction Guard rule version 1.0;
the existing package-scanner rule version is unchanged.
Report history is retention-limited to the newest 32 reports and a 256 MiB
aggregate budget (the current report is always retained). Alert envelopes are
bounded to 2,048, with at most 256 acknowledged envelopes retained when space
permits. Pruning never approves content or removes the manifest's persistent
integrity/review state.

The monitor is installed disabled. After explicit opt-in, its hardened user
service runs after login and every five minutes with network access disabled,
a read-only home, private writable state, low CPU/I/O priority, and AI
credentials removed. A second, separately enabled user timer may process at
most one pending AI job per run using the configured local or cloud provider.
It sends at most 12 KiB of opaque evidence IDs, fixed deterministic reasons,
semantic behavior labels, and deterministic line locations to a tool-free
strict JSON review. It sends no file path or source snippet. AI may return only
advisory rationales mapped to those evidence IDs: it cannot invent or change a
line location, lower deterministic severity, establish trust, claim execution
or compromise, or propose commands. Disabling Instruction Guard AI makes no
provider request.

HIGH/CRITICAL and integrity alerts remain visible through CLI review state and
the tray. When `notify-send` is available, desktop notifications contain only
a generic review prompt, never a path, snippet, username, credential, or AI
text. Acknowledging an alert suppresses an identical notification; it does not
approve the file.

After explicit confirmation, AuraScan can disable only an unchanged,
user-owned, standalone regular instruction file. Settings, hook
configurations, plugin manifests, scripts, shared configurations, and symlinks
remain manual-only. An eligible file is atomically renamed beside itself to a
hidden non-discoverable name, and a private receipt supports exact restoration.
Restore refuses changed or unsafe state, rescans immediately, and returns the
file to unreviewed status rather than trusting it automatically. There is no
automatic quarantine.

This is defense in depth, not a same-user security boundary. Malware already
running as the monitored UID can alter user files or attack AuraScan state;
root malware can disable or deceive the monitor entirely. Corrupt, symlinked,
wrongly owned, or permission-weakened guard state fails closed for review
instead of being overwritten.

The user settings are `AURASCAN_INSTRUCTION_MONITOR_ENABLED`,
`AURASCAN_INSTRUCTION_AI_ENABLED`, and
`AURASCAN_INSTRUCTION_SCAN_MODE=agent-surfaces|all-markdown`. Enabling the
general AuraScan AI provider does not enable Instruction Guard AI or either
Instruction Guard timer.

## Upgrade Preflight

`aurascan upgrade` is an optional first-class upgrade front door for
Arch-family systems. It previews the pending upgrade, checks local breakage
risks, then hands off to pacman or a supported AUR helper when it is reasonable
to continue.

```bash
aurascan upgrade
aurascan upgrade --dry-run
aurascan upgrade --verbose
aurascan upgrade --json
aurascan upgrade --aur-helper shelly
aurascan upgrade --no-ai
aurascan upgrade --no-config-drift
aurascan upgrade --no-kernel-module-autopilot
aurascan upgrade --no-security-audit
```

The repo-package preview uses pacman, and the final repo-only handoff is:

```bash
sudo pacman -Syu
```

When `paru`, `yay`, or `shelly` is selected or auto-detected, AuraScan also
queries AUR updates and hands off to that helper. `paru` and `yay` use `-Syu`;
Shelly 3 uses `shelly upgrade all --no-flatpak --no-appimage`; AuraScan detects
and retains the older `shelly upgrade-all` syntax for Shelly 2 installations.
This keeps the handoff aligned with AuraScan's repo/AUR preflight scope. After a
passing preflight, AuraScan may add the helper's no-confirm option so the
already-approved upgrade does not ask a second default-no question; use
`--no-trusted-handoff` to keep the helper confirmation prompt. If no supported
helper is available, AuraScan still warns about installed foreign packages that
may need rebuilds after library, kernel, compiler, Python, Qt, or Electron
updates.

Upgrade preflight is not a safety guarantee. It checks for practical pitfalls
such as low `/boot` or root space, CachyOS kernel movement when CachyOS kernel
packages are installed, initramfs or
bootloader-sensitive updates, ignored packages that can create partial
upgrades, replacements/conflicts, known AUR campaign exposure, unresolved
official HIGH/CRITICAL package advisories, AUR rebuild risk, local foreign-package
dependency/conflict metadata, and pending `.pacnew`/`.pacsave` config drift. A
clean preflight means AuraScan did not find these signals; pacman, hooks,
packages, or local configuration can still fail.

Before handing control to Shelly or pacman, AuraScan labels the output boundary
so mirror, download, conflict, and replacement messages are not mistaken for
AuraScan errors. Repository conflicts and replacements are described as package
transition metadata while remaining advisory. After a successful command,
AuraScan verifies every planned repository version before explaining that any
earlier mirror-specific `NotFound`/404 messages were recovered by fallback
mirrors. A failed or unverifiable transaction never receives that reassurance.

Kernel/Module Autopilot is enabled by default inside `aurascan upgrade`. It
checks kernel package families, running-kernel mapping, standard Arch kernel
families such as `linux`, `linux-lts`, `linux-zen`, and `linux-hardened`,
CachyOS prebuilt NVIDIA module packages when present, DKMS headers/status,
external module families, fallback kernel evidence, and reboot need. When
AuraScan can prove the module state is covered, the terminal report says so
directly. When a deterministic missing package fix is available, AuraScan shows
the exact package command and asks before running it; `--yes` does not silently
apply these extra fixes. After a successful upgrade handoff, AuraScan runs a
post-upgrade kernel/module aftercare check and reports whether a reboot is
expected. It never reboots automatically.

If HIGH or CRITICAL preflight risk is found, AuraScan asks for one extra
confirmation before running the package-manager command:

```text
AuraScan found upgrade risks. Continue anyway? [y/N]
```

This is not a hard-blocker bypass model. AuraScan does not force system
maintenance to stop; it gives you a clear checkpoint before continuing. Pacman
or the AUR helper will still show its normal confirmation and may still fail.

AI review is optional and raise-only. When AI is configured and not disabled
with `--no-ai`, AuraScan sends a redacted structured summary of package names,
versions, deterministic findings, and selected local system facts. It does not
send API keys, environment variables, full command output, or file contents.
AI may raise a preflight risk or add an advisory `UPG-AI-RISK`, but it cannot
lower deterministic risk, mark an upgrade safe, or hard-block by itself.

The config keys are `AURASCAN_UPGRADE_PREFLIGHT_ENABLED`,
`AURASCAN_UPGRADE_AUR_HELPER`, `AURASCAN_UPGRADE_PREFLIGHT_AI`, and
`AURASCAN_KERNEL_MODULE_AUTOPILOT_ENABLED`.
Supported helper values are `auto`, `paru`, `yay`, `shelly`, and `none`.
`aurascan upgrade --enable-preflight` can temporarily override a disabled
preflight setting, while `--disable-preflight` disables it for that invocation
and does not run the upgrade command.

## Contextual Follow-Up Assistant

When an AI provider is configured, interactive foreground upgrade, incident,
maintenance, and config-drift workflows offer:

```text
Ask AuraScan about this result, or press Enter to finish:
```

Existing apply or continue prompts accept `?` to open the same assistant before
returning to the unchanged confirmation. Results can also be reopened later:

```bash
aurascan ask
aurascan ask --latest
aurascan ask CONTEXT_ID
aurascan ask --facts-only
```

Each session is limited to eight questions and twelve provider requests. A
question may use a second request when AI selects a known bounded local probe
and AuraScan returns its normalized result. AI responses must use strict JSON
and may reference only fact, probe, and action IDs generated by AuraScan.
Unknown IDs, commands, scripts, package targets, paths, and file edits are
discarded in this guarded assistant.

Questions about hardware, memory pressure, temperatures, cooling, drivers,
microcode, BIOS, or firmware automatically run a bounded read-only hardware
probe before the first AI answer. When the local interfaces expose them,
AuraScan supplies CPU and GPU models, RAM capacity and DIMM topology, mainboard
and BIOS versions, current driver/module versions, hwmon temperatures and fan
states, memory pressure, and normalized current-boot hardware-error counts.
It compares relevant installed support packages with the configured local
repository databases and uses `fwupd` for supported firmware-update checks.

Hardware coverage remains evidence-based. AuraScan labels stale repository
metadata, unsupported `fwupd` devices, unavailable sensors, and inaccessible
SMBIOS data instead of claiming they are current or healthy. SMBIOS usually
provides RAM type and configured speed, but not exact primary timings; AuraScan
does not read raw SPD/I2C data. A zero-RPM reading without a hardware alarm is
reported as stopped or unreported, not as a failed fan. Serial numbers, system
UUIDs, raw firmware tables, and arbitrary files are excluded.

If a requested operation maps to an existing verified AuraScan recipe, AuraScan
refreshes local state, previews one combined plan, and asks separately before
execution. Parent `--yes` flags never authorize follow-up actions. AI cannot
run an upgrade, reboot, edit arbitrary files, repair filesystems, change a
bootloader, or turn response text into a command.

Private redacted contexts are retained under
`~/.local/state/aurascan/follow-up/` for 30 days or 50 records.
Questions and AI answers stay in memory and are not written to context files.
JSON,
non-interactive, `--yes`, `--no-ai`, pacman-hook, root-collector, and background
service paths never open chat. Config drift follow-up remains facts-only unless
redacted diff sharing was explicitly allowed for that run.

The interactive commands `/status`, `/stop`, and `/agent ACCESS` are available.
`/agent user-shell` or `/agent root-shell` starts a separate Repair Agent
session only when that access has already been configured; access changes
cannot inherit an existing grant.

## Full-Control Repair Agent

`aurascan agent` reuses a retained AuraScan result but can optionally let the AI
request exact terminal commands:

```bash
aurascan agent
aurascan agent --latest
aurascan agent CONTEXT_ID
aurascan agent --access user-shell
aurascan agent --access root-shell
```

Access is layered:

- `guarded` is the default and uses only existing AuraScan-owned probes and
  verified repairs. AI cannot generate commands in guarded mode.
- `user-shell` may request arbitrary commands under the current user after a
  foreground session prompt.
- `root-shell` may request unrestricted root commands. It requires both a
  root-owned policy opt-in and the exact per-session phrase
  `GRANT AI FULL ROOT CONTROL`.

The settings are `AURASCAN_AGENT_ACCESS`, `AURASCAN_AGENT_APPROVAL`,
`AURASCAN_AGENT_OUTPUT_SHARING`, and `AURASCAN_AGENT_SESSION_TIMEOUT`.
`aurascan init` configures them. `/etc/aurascan/agent.conf` separately caps
whether root mode is allowed, its maximum approval mode, and session duration;
it contains no API credential.

Approval defaults to `each-command`, which displays the exact command,
privilege, working directory, reason, and expected result before every run.
`whole-plan` confirms a finite immutable plan, while `session` permits
autonomous commands until expiry or `/stop` and therefore requires stronger
typed consent. Commands are noninteractive, limited to 30 per session, and run
with a minimal environment. Provider requests are limited to 40.

Terminal output is shown locally. AI receives at most 32 KiB per command and
128 KiB per session. Output is redacted by default; `full` requires typing
`SHARE FULL TERMINAL OUTPUT` for that session. Questions and AI answers remain
in memory. Private command hashes, redacted command renderings, approvals,
exit states, and bounded redacted output are retained under
`~/.local/state/aurascan/agent/` for 30 days or 50 sessions.

Before root mode, AuraScan asks the privileged broker to create and validate a
Btrfs/Snapper snapshot. If that is unavailable, continuing requires typing
`CONTINUE WITHOUT ROLLBACK`. A snapshot does not protect other disks,
firmware, credentials, remote services, networking, or every system file.

The unprivileged AI process never gives API credentials to the root broker.
Root grants are short-lived and bound to the invoking UID, process identity,
terminal, context fingerprint, approval ceiling, and capability. Root
manifests are private under `/var/lib/aurascan/agent/`.

This mode is deliberately dangerous. Once an unrestricted root command starts,
it can modify AuraScan, disable auditing, escape best-effort process controls,
destroy data, or change firmware, networking, authentication, and security
policy. Software cannot make that authority safe. Use it only with commands you
have read and accepted, preferably in `each-command` mode with current backups.

The agent is foreground-only. JSON output, noninteractive workflows, pacman
hooks, package-manager `--yes`, incident collectors, background services, and
AuraScan Recovery cannot start it. Background Safe Autopilot retains its
two-recipe deterministic allowlist.

## AuraScan Updater Tray Icon

`aurascan updater` runs the optional AuraScan Updater system-tray applet. It is
an AuraScan-owned icon that can sit beside Cachy-Update and Shelly without
replacing either launcher.

```bash
aurascan updater
aurascan updater --status
aurascan updater --install-autostart
aurascan updater --remove-autostart
aurascan updater --no-tray
```

The tray menu provides terminal-native AuraScan flows and two checkable
Instruction Guard controls:

- Run AuraScan Upgrade: `aurascan upgrade`
- Resolve System Findings: `aurascan incidents --resolve`
- Review Agent Files: `aurascan instruction-audit --review`
- Run System Maintenance Scan: `aurascan incidents --run-maintenance`
- Instruction Guard Background Scan: enable or disable the login and
  five-minute deterministic monitor
- Instruction Guard AI Analysis: separately enable or disable scheduled,
  raise-only AI review
- AuraScan Settings: `aurascan init`

The two checkmarks refresh when the tray starts and whenever its right-click
menu opens. Changes run asynchronously through the same transactional
`instruction-audit` controls used by the CLI, so the tray remains responsive
and partial configuration changes are rolled back. AI analysis can be enabled
only when an existing local or cloud provider is ready. While state is being
checked, or when private configuration and user-service state disagree, the
controls are disabled and their tooltips direct the user to Settings or
`aurascan doctor`. Success and failure notifications remain generic and never
include paths, command output, credentials, or provider secrets.
AuraScan temporarily disables its tray Quit action during an enable/disable
transaction so it cannot interrupt a configuration rollback.

Config drift is handled automatically before and after `aurascan upgrade`, so
it is intentionally omitted from the beginner-focused tray menu. The
standalone `aurascan config-drift` command remains available for advanced or
out-of-band maintenance.
`aurascan doctor` remains available from a terminal for installation and
configuration troubleshooting, but is intentionally omitted from the routine
tray workflow.
The report-only `aurascan upgrade --dry-run` command likewise remains available
for advanced terminal use; the normal upgrade action always runs preflight
before handing control to the package manager.

Double-clicking the icon runs `aurascan upgrade` where the desktop environment
delivers double-click activation. The right-click menu is the reliable fallback
on desktops that handle tray activation differently.

Autostart is per-user and reversible. The wizard can install
`~/.config/autostart/aurascan-updater.desktop` and a matching application
launcher under `~/.local/share/applications/`; it does not modify
Cachy-Update, Shelly, or system desktop files. PyQt6 or PySide6 is required only
for the tray applet, not for normal AuraScan scans.

The tray refreshes incident and Instruction Guard state every five seconds. Its
normal icon changes to maintenance-due, attention, or critical variants when
the weekly scan is overdue or unreviewed findings need attention. Instruction
Guard severity takes priority when it is higher, and its menu action routes to
the agent-file review rather than the incident flow. Clean scans are silent.
Desktop notifications are reserved for HIGH/CRITICAL findings and repeated
crashes unless separately opted-in background AI completes an analysis, in
which case the tray shows one bounded completion summary. Instruction Guard
notifications are generic and contain no paths or evidence. The icon remains
changed until the applicable guided review completes or report retention
expires; a verified Safe Autopilot repair may clear only the incident category
it actually resolved.

The config keys are `AURASCAN_UPDATER_TRAY_ENABLED`,
`AURASCAN_UPDATER_AUTOSTART`, and `AURASCAN_UPDATER_TERMINAL`.

## Incident Recovery Assistant

`aurascan incidents` diagnoses bounded system and application crash evidence,
explains likely causes, and can apply a small set of AuraScan-owned repair
recipes after confirmation.

```bash
aurascan incidents
aurascan incidents --resolve
aurascan incidents --last-boot --dry-run
aurascan incidents --current-boot --no-ai
aurascan incidents --history
aurascan incidents --show INCIDENT_ID
aurascan incidents --json
aurascan incidents --run-maintenance
aurascan incidents --maintenance-status
aurascan incidents --enable-background-ai
aurascan incidents --background-ai-status
aurascan incidents --auto-repair safe
```

With no explicit target, AuraScan opens a pending previous-boot incident when
one exists and otherwise scans the current boot. `--dry-run` never repairs.
`--json` is report-only unless paired with `--yes`, and a truncated scan never
gets a default-yes repair prompt.

`--resolve` is the tray's single incident workflow. AuraScan opens the
highest-priority pending evidence and, when incident AI is enabled, uses a
two-pass AI-guided repair planner. The first pass may select only opaque IDs
for AuraScan-owned read-only probes. AuraScan runs those probes locally,
constructs independently verified repair actions, and lets the second pass
explain and prioritize only known action IDs. Eligible AuraScan-owned repairs
are applied as one plan after confirmation, followed by deterministic
aftercare. When no safe automatic
repair exists, it explains that the evidence is historical and acknowledges
the pending alert. The tray then returns to normal while reports remain in
history. A normal icon means findings were handled or reviewed; it is not a
claim that historical crashes were erased or that an unverified cause was
fixed. Weekly maintenance advances bounded journal/coredump checkpoints, so
acknowledged historical events do not create the same tray alert again. A new
crash creates a new alert, while an explicit scan of an old boot can still show
its preserved history.

After a foreground incident or manual maintenance scan, the contextual
follow-up assistant can explain the report or request additional known local
probes. Any newly prepared incident repair rejoins the same guarded
confirmation and root-side revalidation path.

Interactive incident scans keep a stage indicator and elapsed timer visible
while AuraScan reads the journal and coredumps, verifies repair recipes, and
performs optional AI correlation. These honest stages replace a guessed
percentage; JSON output and unattended monitor captures remain quiet.
Each incident AI request has a 60-second response timeout and is not retried
immediately. Timeouts, provider/network failures, and responses that fail the
strict JSON contract are reported separately. In every case deterministic
diagnostics and independently verified repairs remain usable. An unprivileged
foreground scan silently skips root-only pstore access; the root monitor still
reports a pstore permission failure because that indicates a collector problem.

The optional root monitor is installed disabled. Its weekly timer is also
installed disabled, and both are enabled together only through
`aurascan init --enable-incident-monitor` or `aurascan incidents
--enable-monitor`. The boot service performs one read-only previous-boot scan
after journal flush. The persistent weekly timer incrementally scans the
current boot, runs a bounded baseline when monitoring is first enabled, and
stores root-only journal/coredump checkpoints so it does not repeatedly scan a
long-running boot. The root collectors have no network access, make no AI
requests, and never execute repairs themselves. After successful collection
they may trigger the separate root Safe Autopilot oneshot. That service also
has no network access or AI credentials and exits without action unless its
root-owned policy is explicitly set to `safe`.

Background AI is a second, per-user opt-in. When enabled, a hardened
`systemd --user` timer processes at most one highest-priority marker every five
minutes while that user is logged in. It uses the user's existing `0600` AI
configuration, bounded redacted evidence, and provider retries of 15 minutes,
1 hour, 6 hours, then 24 hours. It may run the same bounded read-only probes and
prepare broader repairs, but it cannot run `sudo`, invoke repair execution, or
write system paths. A matching private prepared plan can be reused for six
hours; Resolve refreshes its probes and every privileged recipe still performs
fresh root-side validation. The tray asks it to run immediately for a new
marker and shows one concise completion notification, including how many
verified actions await confirmation. Provider failure leaves the alert
available for the normal **Resolve System Findings** flow.

Safe Autopilot defaults to `off`. In `safe` mode it may apply only a proven
stale pacman-lock recovery or a verified mirrorlist restoration. Both recipes
are reversible, freshly revalidated as root, limited to two actions per run,
recorded in a private manifest, and protected by a 24-hour identical-action
cooldown. Incomplete/truncated reports and reports with unresolved
HIGH/CRITICAL findings are refused. Package operations, DKMS, initramfs,
services, cache deletion, reinstalls, filesystems, bootloaders, and rebooting
still require the foreground user flow.

Weekly collection uses the same evidence limits as manual diagnostics. A
truncated scan advances only through its last processed cursor and marks
maintenance due so the next run can continue. Public maintenance status
contains only scan times and collection health. Pending markers contain only
marker type, scan
generation, boot ID, UID scope, category severities, resolved categories,
coarse repair state, counts, and a repeated flag, never crash evidence, paths,
package names, application names, AI text, or commands.

Evidence collection is bounded to 2,000 journal records, 256 KiB of local
evidence, and 200 coredumps. AuraScan does not inspect core memory, process
environments, arbitrary files, or complete command lines. Persisted reports are
redacted and separated by user scope. Foreground incident AI runs when a user
opens an incident; separately opted-in background AI can run in that user's
logged-in session. Both receive at most 80 matched excerpts and 12,000 redacted
characters per request. AI-guided repair planning uses at most two requests per
incident: triage chooses from at most 24 local probe candidates, then a final
review sees normalized results from at most 12 executed probes. `facts-only`
mode sends structured findings without log excerpts.

AI may request up to six known probe IDs, explain findings, and recommend
existing action IDs. Probe targets are resolved from trusted local evidence
before the request; the provider never supplies package names, paths, units, or
arguments that AuraScan executes. AI cannot generate commands, suppress
deterministic findings, approve repairs, or mark an incident repaired. AuraScan
reconstructs every privileged command from trusted current state and reruns
recipe preconditions as root. An AI correlation may
not blame unrelated packages merely because they were updated in the same boot.

Confirmed repair recipes cover a proven stale pacman lock, guarded repository
mirror recovery, verified kernel/module support packages, DKMS autoinstall with
matching headers, backed-up initramfs rebuilds with boot-space checks,
noncritical service restart/reset, bounded package-cache cleanup, and exact
official-package reinstall from a matching signed local archive. AuraScan does not automate filesystem repair.
It also does not automate partition or bootloader edits, authentication
configuration, firmware changes, user-data deletion, AUR rebuilds, or rebooting.

The user config keys are `AURASCAN_INCIDENT_MONITOR_ENABLED`,
`AURASCAN_INCIDENT_AI_ENABLED`, `AURASCAN_INCIDENT_AI_EVIDENCE`, and
`AURASCAN_INCIDENT_BACKGROUND_AI`. Evidence mode is `redacted` or
`facts-only`. The root-owned `/etc/aurascan/incident-autopilot.conf` accepts
only `AURASCAN_INCIDENT_AUTO_REPAIR=off|safe` and contains no API credential.

## AuraScan Recovery Environment

`aurascan recovery` manages an optional x86-64 recovery environment for Arch
Linux, EndeavourOS, Manjaro, and CachyOS. It is intended for systems that cannot
reach the normal desktop or console reliably enough to run the ordinary
Incident Recovery Assistant.

```bash
aurascan recovery --status
aurascan recovery --install
aurascan recovery --refresh
aurascan recovery --remove
aurascan recovery --dry-run --install
aurascan recovery --download-iso
aurascan recovery --write-usb /dev/sdX
```

The internal image is built locally with mkosi's `mkosi-initrd` profile and `ukify` from an
installed alternate/LTS kernel when available. AuraScan creates a
credential-free zipapp containing the exact installed AuraScan code, builds in
private staging, validates the complete image for forbidden key/profile
material, signs it with an already enrolled sbctl-compatible owner key when
Secure Boot is enabled, and then atomically installs
`/boot/EFI/Linux/aurascan-recovery.efi`. Existing recovery image and
bootloader configuration backups are retained. Secure Boot installation is
refused when AuraScan cannot prove an enrolled signing key; USB recovery remains
available.

Limine uses an AuraScan-owned marked EFI chainload block, systemd-boot discovers
the UKI under `EFI/Linux`, and GRUB uses an AuraScan-owned generated chainloader
script. Internal installation requires x86-64 UEFI. The release USB image is a
hybrid BIOS/UEFI Archiso build from `packaging/recovery/`; its packaged manifest
must contain a pinned SHA-256 digest before download is enabled. The guided USB
writer accepts only an unmounted removable whole disk, rejects the running/root
disk, requires the exact device path to be typed, flushes the device, and
verifies the written bytes.

Package installation never installs a recovery boot entry. The wizard offers
installation with default Yes only after UEFI, ESP space/mount, supported
bootloader, kernel, `mkosi`, `ukify`, and any required enrolled Secure Boot key
checks pass. The root-owned
`/etc/aurascan/recovery.conf` records only enablement, adapter, refresh policy,
opted-in UID, Wi-Fi-profile permission, image version, and refresh status. It
contains no AI key or Wi-Fi credential. An enabled automatic refresh uses a
post-transaction hook after relevant AuraScan, kernel, Python, firmware,
networking, or storage packages change. Refresh failure leaves the previous
image bootable, does not fail the completed pacman transaction, and appears in
`aurascan doctor`.

Inside recovery, AuraScan discovers Arch-family targets read-only across
Btrfs, ext4, XFS, LUKS2, LVM2, and mdraid layouts. Filesystem checks remain
read-only. NetworkManager starts automatically; Ethernet and USB tethering use
DHCP. Saved Wi-Fi profiles are used only with recovery permission, and only
regular root-owned `0600` NetworkManager profiles are copied into volatile
`/run` storage. Manual open, WPA2, WPA3, and hidden networks are supported.
Passwords travel through NetworkManager's secret-agent input, never command
arguments or reports. Captive portals and enterprise/802.1X remain unsupported;
use another network, phone tethering, or offline recovery.

Offline deterministic diagnostics start first. AuraScan checks package locks,
repository health, interrupted transactions, kernel/module trees, initramfs,
boot-critical config drift, free space, snapshots, the ESP, and the detected
bootloader. Cloud provider AI runs automatically only when recovery AI was
separately enabled and a usable non-captive connection exists. A loopback local
provider can run without external connectivity when its compatible server is
available inside the recovery environment. AuraScan validates the opted-in
user's `0600` provider config from the mounted target; otherwise it can accept a
session-only key that is never persisted. Provider failure does not block the
deterministic plan.

Recovery reuses the two-pass guarded planner. AI can select only opaque local
probe IDs and then prioritize only independently verified action IDs. It cannot
provide package names, paths, units, arguments, file edits, or commands for
execution. The combined plan can cover stale locks, mirror restoration, bounded
cache cleanup, complete signed pacman transactions, matching kernel/header and
DKMS recovery, backed-up initramfs rebuilds, boot config drift, exact signed
cached packages, and a proven noncritical boot-blocking service. Every action is
reconstructed from current target state and revalidated as root immediately
before execution.

Snapshot restoration always creates a pre-recovery snapshot first and requires
typing `RESTORE SNAPSHOT <id>`. Full Limine, systemd-boot, or GRUB reinstallation
requires positive loader/ESP detection, backups, post-validation, and typing
`REINSTALL BOOTLOADER`. Reinstall recipes update loader files without changing
firmware variables. `--yes` cannot bypass either phrase. AuraScan never
formats filesystems, changes partitions, performs filesystem repair, enrolls
Secure Boot keys, flashes firmware, changes authentication policy, deletes user
data, runs arbitrary AI commands, or reboots automatically.

Private redacted reports and repair manifests are stored under
`/var/lib/aurascan/recovery/` with `0700` directories and `0600` files. If the
target is not writable, the report remains in recovery RAM for export to
removable media. A successful scan or AI explanation cannot guarantee that
software, storage, firmware, or hardware damage is repairable.

Recovery user settings are `AURASCAN_RECOVERY_AI_ENABLED`,
`AURASCAN_RECOVERY_AUTO_REFRESH`, and
`AURASCAN_RECOVERY_WIFI_PROFILES=auto|ask|never`. Recovery AI reuses
`AURASCAN_INCIDENT_AI_EVIDENCE=redacted|facts-only`.

## Config Drift Assistant

`aurascan config-drift` finds `.pacnew` and `.pacsave` files, explains what
they mean, prepares safe fixes, and creates backups before every write.

```bash
aurascan config-drift
aurascan config-drift --dry-run
aurascan config-drift --json
aurascan config-drift --yes
aurascan config-drift --ai-diffs
```

`aurascan upgrade` runs the assistant before the package-manager handoff and
again after it exits, unless disabled with `--no-config-drift` or config. The
assistant auto-plans low-risk fixes such as duplicate `.pacnew` files,
missing-target installs, comments-only changes, and mirrorlist-style updates.
Sensitive files such as `pacman.conf`, bootloader/initramfs config, sudo/PAM,
networking, users/groups, SSH, systemd, and security policy are treated with
extra caution.

Before applying any fix, AuraScan backs up the active config and drift file
under `/var/lib/aurascan/config-drift/<run-id>/` with a JSON manifest. `.pacsave`
files are explained but not restored or deleted automatically in v1.

AI diff review is optional and opt-in. The configured AI provider sees config diffs only when
`--ai-diffs` is passed or `AURASCAN_CONFIG_DRIFT_AI_DIFFS=always` is configured.
Diffs are bounded and redacted first, but AuraScan still treats AI as advisory:
AI cannot bypass backups, deterministic file classification, or sensitive-file
confirmation rules.
Contextual follow-up does not weaken this gate: without explicit diff consent,
it receives only file classifications, action summaries, and risk metadata.

The config keys are `AURASCAN_CONFIG_DRIFT_ENABLED` and
`AURASCAN_CONFIG_DRIFT_AI_DIFFS`, where AI diff policy is `ask`, `never`, or
`always`.

## makepkg Wrapper

`aurascan-makepkg` is the preferred AUR-helper integration point when the helper
can be configured to use a custom makepkg command.

```bash
aurascan-makepkg --syncdeps
aurascan-makepkg --aurascan-deep-static --syncdeps
aurascan-makepkg --aurascan-json --syncdeps
```

The wrapper scans the current directory's `PKGBUILD` before invoking the real
`makepkg`. AuraScan-only flags use the `--aurascan-*` prefix and are stripped
before makepkg receives its arguments. If AuraScan blocks or requires review,
makepkg is not invoked by default.

The wrapper protects the pre-build phase. It does not sandbox makepkg, install
packages, or make package code safe after makepkg starts running build steps.

## Pacman Hook

The release-safe pacman hook template is `packaging/arch/aurascan.hook`. The
root `aurascan.hook` mirrors that release-safe template. It calls the installed
`/usr/bin/aurascan` executable and does not point at a source checkout, virtual
environment, or developer home directory.

A pacman hook scans already built package archives before the pacman
transaction. This is useful for archive and install-metadata review, but it is
too late to protect against malicious PKGBUILD build-time logic that may have
run during package creation.

The makepkg wrapper and pacman hook are different tools:

- `aurascan-makepkg` scans before makepkg executes package build functions.
- The pacman hook scans built package archives before pacman installs them.

The current hook is conservative and does not provide a verified pacman
transaction context provider for smart update fast paths.

`pip install` does not install pacman hooks. Plainly, pip install does not install pacman hooks. Pacman hooks require root or
package-manager installation. The preferred release path is an Arch package
that installs the hook to `/usr/share/libalpm/hooks/aurascan.hook` and removes
it when the package is uninstalled. `aurascan init` treats that packaged hook as
already active and does not copy it into `/etc`. Manual installation to
`/etc/pacman.d/hooks/` is possible, but should be done carefully. Do not leave a
hook behind that points to a missing executable; remove the hook or reinstall
AuraScan before continuing pacman transactions.

The hook uses pacman's `NeedsTargets` mode. AuraScan reads target names from
stdin, scans an existing target path when one is provided, or looks for the
latest matching `.pkg.tar.zst` file in `/var/cache/pacman/pkg`. Missing archive
targets are reported as warnings and do not block by themselves. Blocking
findings make AuraScan exit non-zero, which should stop the pacman transaction.
If `clamscan` is unavailable, AuraScan reports that AV scanning was skipped and
continues with the remaining checks. If `/usr/bin/aurascan` is missing, pacman
cannot run the hook command; recover by reinstalling AuraScan or removing the
stale hook from the hook directory.

## Review Acceptance

Some findings require manual review but are not hard blockers. In the makepkg
wrapper, eligible manual-review findings produce a review token. After reading
the findings, the same exact scan can be accepted:

```bash
aurascan-makepkg --aurascan-accept-review arv-... --syncdeps
aurascan-makepkg --aurascan-accept-review arv-... --aurascan-review-reason "reviewed warning" --syncdeps
```

By default, review acceptance is one-time. `--aurascan-remember-review` records
a reusable decision for the same exact scan fingerprint. `--aurascan-review-once`
forces one-time behavior. `--aurascan-review-expire-days N` adds an expiry.

List or revoke decisions:

```bash
aurascan-makepkg --aurascan-list-review-decisions
aurascan-makepkg --aurascan-revoke-review <decision_id>
aurascan-makepkg --aurascan-json --aurascan-list-review-decisions
```

Review acceptance is not clean trust. It does not create a trusted baseline for
smart update fast paths. Hard blockers cannot be accepted through ordinary
review. Confirmed malware signatures, checksum mismatches, invalid signatures,
signer fingerprint mismatches, unsafe archive findings, deterministic CRITICAL
findings, and findings marked as blocking remain stops.

## Update Scan Policies

AuraScan supports update scan policy scaffolding:

- `full`: normal conservative scan path.
- `smart`: may use a fast path only with proven update context, an accepted
  baseline, and trust-diff approval.
- `new-only`: weaker mode that may skip already-installed updates only when
  update context is proven or explicitly user-asserted with opt-in.

`new-only` is weaker protection. Plainly, new-only is weaker protection because malicious behavior can be introduced in
an update. A skipped update does not become a trusted baseline.

"No new dependencies" is not enough to skip a scan. Package name, dependency
stability, AUR metadata, and version strings alone are also not proof that a
scan is a safe update.

`--scan-context auto` uses a local package database provider. It reads local
pacman DB metadata without root, package installation, makepkg, package-code
execution, or network access. If identity, installed state, candidate version,
version comparison, or split-package mapping is ambiguous, AuraScan falls back
to normal conservative behavior.

Manual `--scan-context update` is user-asserted, not provider-verified. It can
participate in smart or new-only decisions only with
`--allow-user-asserted-update-context`, and reports label it as user asserted.

## Privacy And External Tools

Default scans are deterministic and local unless AI analysis has been
explicitly enabled or a legacy-compatible cloud configuration has an API key
but no explicit enable flag. Local providers never enable implicitly. The
first-run wizard writes an explicit `AURASCAN_AI_ENABLED` value so the user's
choice is clear. When enabled, package AI analysis may send package
metadata, PKGBUILD text, and install-script text to the configured provider.
For `lmstudio` and `llamacpp`, that provider is a loopback HTTP server; AuraScan
does not redirect or proxy the request to another host. Config drift diff review
has an additional opt-in gate and sends only redacted bounded diffs.
Incident AI normally runs when the user opens an incident. A separate explicit
opt-in permits background AI only in the logged-in user service. The root boot,
weekly, and Safe Autopilot services have no network access and never load API
credentials. Incident evidence is bounded and redacted before persistence or
AI use, and `facts-only` mode omits raw evidence excerpts. See
[`docs/PRIVACY.md`](docs/PRIVACY.md) for process and storage boundaries.

Instruction Guard's deterministic user service is a separate opt-in and runs
without network access or AI credentials. Its AI assistant has another consent
bit, processes at most one queued job per timer run, and receives no more than
12 KiB of redacted suspicious evidence. Agent-file reports and manifests are
private user security state; public notifications and tray status never include
file paths, snippets, usernames, credentials, or provider text.

Contextual follow-up uses the same configured foreground provider consent. It
sends at most 12,000 redacted characters per request and accepts only
AuraScan-generated opaque fact, probe, and action IDs. Private source contexts
are retained with `0700`/`0600` permissions, while questions and AI answers are
not persisted. Follow-up never runs in root collectors or pacman hooks.
Hardware-aware questions may include bounded model, capacity, version, sensor,
memory-pressure, and normalized hardware-error facts. AuraScan excludes serial
numbers, UUIDs, raw DMI/SPD data, and raw journal text from that hardware
summary. Firmware and driver checks are read-only and never install an update.

Repair Agent shell access is a separate foreground authority. Redacted output
sharing is the default, raw output requires a typed session grant, and API keys
are removed from the executor environment. Private audits retain command hashes
and redacted command/output material. Enabling `root-shell` means accepting
that a root command can defeat these software boundaries after execution
begins.

Recovery AI has a separate consent bit. Neither the locally built UKI nor the
release ISO contains an API key, user config, saved WLAN profile, hostname,
home path, or incident evidence. A validated target-user provider config is
read only after target mount and runtime setup; an optional session key remains
in memory. Recovery AI receives the same bounded redacted/facts-only evidence
and opaque probe/action IDs as foreground incident AI. A local provider's
`127.0.0.1` address refers to the recovery environment itself, not the installed
system. Recovery neither starts nor forwards LM Studio or `llama-server`; if no
compatible server is already running inside recovery, the AI step remains
unavailable and deterministic recovery continues without a cloud fallback.

Supported AI provider IDs are `openai`, `anthropic`, `deepseek`, `gemini`, and
`openrouter`, plus the local `lmstudio` and `llamacpp` providers.
Provider-specific keys for cloud providers use `AURASCAN_OPENAI_API_KEY`,
`AURASCAN_ANTHROPIC_API_KEY`, `AURASCAN_DEEPSEEK_API_KEY`,
`AURASCAN_GEMINI_API_KEY`, or `AURASCAN_OPENROUTER_API_KEY`. Legacy
`AURASCAN_AI_KEY` remains supported for existing setups. Local providers use
the optional `AURASCAN_LOCAL_AI_API_KEY`; their endpoint may be overridden with
`AURASCAN_AI_BASE_URL` subject to the loopback-only policy.

Deep static source acquisition can contact source hosts and, unless disabled,
a configured keyserver for PGP key lookup. The metadata-only tuning helper
fetches only PKGBUILD and `.SRCINFO` text from the AUR and does not download
declared sources.

External tools are optional where appropriate. Missing ClamAV, GPG, makepkg,
pacman, or vercmp should fail gracefully in the paths that can proceed without
them. Some workflows, such as invoking the makepkg wrapper after a successful
scan, require a real makepkg executable.

## False Positives

AuraScan is intentionally cautious. System service files, cron jobs, dynamic
shell evaluation, checksum changes, signature metadata, and install hooks can
all be legitimate. The terminal presenter tries to explain what was checked,
what was not proven, and what action is recommended.

When a finding is unclear, review the evidence. Do not treat a warning as proof
of malicious intent, and do not treat a clean report as proof of safety.

## Tests And Tuning

Run the core validation:

```bash
python -m compileall aurascan tests tools
.venv/bin/python -m pytest -q
.venv/bin/python tools/audit_presenter_coverage.py
.venv/bin/python tools/audit_presenter_coverage.py --strict
.venv/bin/python tools/audit_presenter_coverage.py --strict-medium
```

Run the metadata-only AUR warning tuning helper:

```bash
.venv/bin/python tools/aur_warning_tune.py --package-list-file tools/package_lists/aur-warning-tune-mixed.txt --limit 50
.venv/bin/python tools/aur_warning_tune.py --package-list-file tools/package_lists/aur-warning-tune-mixed.txt --output-markdown tools/reports/aur-warning-tune.md
```

Metadata-only tuning is opt-in. Live AUR tuning is not part of normal pytest.

## License

AuraScan is released under the MIT License. See [LICENSE](LICENSE).

## Threat Model

AuraScan focuses on reducing package-install risk from malicious or suspicious
packaging behavior, unsafe source archives, weakened source integrity,
dangerous static patterns, suspicious update drift, and known malware
signatures when local scanners are available. Its optional Agent Instruction
Guard also detects suspicious content and integrity changes in recognized
AI-agent control files through bounded periodic static scans.

It is a review and blocking layer, not a complete endpoint security system.
Use it alongside normal Arch-family package trust practices, source review,
maintainer reputation checks, careful review of links and pasted commands, and
system backups. The Instruction Guard does not synchronously intercept file
access, inspect running processes, or establish a security boundary against
same-UID or root malware.
