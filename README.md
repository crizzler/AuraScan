# AuraScan

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
The optional AuraScan Recovery boot environment extends those guarded workflows
to an installed OS that cannot boot normally, with deterministic offline
diagnostics and separately consented network AI.

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

AuraScan currently provides six practical entry points:

- `aurascan --pkgbuild ./PKGBUILD` reviews package build metadata before trust.
- `aurascan-makepkg` scans before handing control to `makepkg`.
- `aurascan upgrade --dry-run` previews an Arch-family upgrade and reports
  pacman, AUR helper, kernel/module, config drift, and AI-raised risks.
- `aurascan config-drift --dry-run` explains `.pacnew` and `.pacsave` files and
  prepares safe fixes with backups.
- `aurascan incidents --dry-run` diagnoses system and application crashes from
  bounded local logs without applying repairs.
- `aurascan recovery --status` manages an optional local recovery boot image;
  plain `aurascan recovery` inside that image starts the guided recovery UI.

## Quickstart

For the latest public source checkpoint, use the GitHub releases page:

```text
https://github.com/crizzler/AuraScan/releases
```

For a development checkout, install AuraScan and launch the setup wizard:

```bash
python -m pip install -e ".[test]" && python -m aurascan init
```

Then verify the local setup:

```bash
python -m aurascan doctor
```

AuraScan is not currently published to official distribution repositories. The
public Arch/AUR package recipe lives under `packaging/arch/` and tracks the
latest tagged GitHub release with a fixed source checksum. Until an AUR package
is published, build the package from this repository:

```bash
git clone https://github.com/crizzler/AuraScan.git
cd AuraScan/packaging/arch
makepkg -si
aurascan init
aurascan doctor
```

Installation does not auto-run the wizard, collect API keys, write user config,
or install local `/etc` hooks as a side effect. Setup starts only when you run
`aurascan init` or `python -m aurascan init`.

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

For development:

```bash
python -m pip install -e ".[test]"
```

This installs the `aurascan` and `aurascan-makepkg` console scripts into the
active environment. It does not install pacman hooks and does not run the
wizard.

The Arch/AUR packaging recipe installs `/usr/bin/aurascan`,
`/usr/bin/aurascan-makepkg`, the pacman hook template, the optional updater
desktop/icon assets, and disabled-by-default incident monitor, user assistant,
Safe Autopilot services, recovery image profiles, and a disabled recovery
refresh hook. It does not build a UKI, alter an ESP, or add a boot entry during
package installation. It
also installs a non-interactive post-install message that points users to
`aurascan init` and `aurascan doctor`. Review it before publishing or installing
it on a real system.

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
summaries.

Default scans do not download declared sources, clone upstream repositories,
fetch PGP keys, run GPG, run makepkg, install packages, or execute package code.
The default scan context is `unknown`, which keeps update fast paths disabled.

Deep static source inspection is opt-in: --deep-static is explicit. It safely acquires and inspects declared source
archives without executing package code. In this mode AuraScan may verify
detached signatures in an isolated temporary GPG home. Automatic key lookup is
limited to explicit source acquisition/deep-static flows and can be disabled
with `--no-auto-key-fetch` or `--offline`.

## What It Does Not Protect Against

AuraScan is not a sandbox, VM, or runtime behavior monitor. It does not make
makepkg safe after it starts running package functions. It does not guarantee
malware detection, and it cannot see behavior hidden in files it did not fetch
or inspect.

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

`aurascan init` can configure an AI provider and save the API key in
`~/.config/aurascan/.env`. API keys are prompted with hidden input and the user
config file is written with restrictive permissions. The wizard recognizes the
release-safe hook installed by the Arch package and does not ask for a redundant
local override. Source or development installs can still repair a local hook at
`/etc/pacman.d/hooks/aurascan.hook` when needed.

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
aurascan init --install-recovery --enable-recovery-ai --enable-recovery-auto-refresh --recovery-wifi-profiles ask
aurascan init --disable-upgrade-preflight
```

Network AI analysis is explicit in wizard-created configs. If you choose
local-only mode, AuraScan writes `AURASCAN_AI_ENABLED=0` and keeps normal scans
local. `aurascan doctor` checks the selected provider, key presence, optional
tools, hook status, and config permissions. It does not contact the provider
unless `--check-ai` is supplied.

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
```

The repo-package preview uses pacman, and the final repo-only handoff is:

```bash
sudo pacman -Syu
```

When `paru`, `yay`, or `shelly` is selected or auto-detected, AuraScan also
queries AUR updates and hands off to that helper. `paru` and `yay` use `-Syu`;
Shelly uses `shelly upgrade-all --no-flatpak --no-appimage` so the handoff
matches AuraScan's repo/AUR preflight scope. After a passing preflight, AuraScan
may add the helper's no-confirm option so the already-approved upgrade does not
ask a second default-no question; use `--no-trusted-handoff` to keep the helper
confirmation prompt. If no supported helper is available, AuraScan still warns
about installed foreign packages that may need rebuilds after library, kernel,
compiler, Python, Qt, or Electron updates.

Upgrade preflight is not a safety guarantee. It checks for practical pitfalls
such as low `/boot` or root space, CachyOS kernel movement when CachyOS kernel
packages are installed, initramfs or
bootloader-sensitive updates, ignored packages that can create partial
upgrades, replacements/conflicts, AUR rebuild risk, local foreign-package
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

The tray menu opens terminal-native AuraScan flows:

- Run AuraScan Upgrade: `aurascan upgrade`
- Resolve System Findings: `aurascan incidents --resolve`
- Run System Maintenance Scan: `aurascan incidents --run-maintenance`
- AuraScan Settings: `aurascan init`

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

The tray refreshes incident state every five seconds. Its normal icon changes to
maintenance-due, attention, or critical variants when the weekly scan is
overdue or unreviewed findings need attention. Clean scans are silent. Desktop
notifications are reserved for HIGH/CRITICAL findings and repeated crashes
unless separately opted-in background AI completes an analysis, in which case
the tray shows one bounded completion summary. The icon remains changed until
the guided resolution completes or report retention expires; a verified Safe
Autopilot repair may clear only the category it actually resolved.

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

Interactive incident scans keep a stage indicator and elapsed timer visible
while AuraScan reads the journal and coredumps, verifies repair recipes, and
performs optional AI correlation. These honest stages replace a guessed
percentage; JSON output and unattended monitor captures remain quiet.

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
bootloader. Network AI runs automatically only when recovery AI was separately
enabled and a usable non-captive connection exists. AuraScan validates the
opted-in user's `0600` provider config from the mounted target; otherwise it can
accept a session-only key that is never persisted. Provider failure does not
block the deterministic plan.

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

AI diff review is optional and opt-in. Network AI sees config diffs only when
`--ai-diffs` is passed or `AURASCAN_CONFIG_DRIFT_AI_DIFFS=always` is configured.
Diffs are bounded and redacted first, but AuraScan still treats AI as advisory:
AI cannot bypass backups, deterministic file classification, or sensitive-file
confirmation rules.

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

Default scans are local unless network AI analysis has been explicitly enabled
or a legacy `AURASCAN_AI_KEY` environment variable is present. The first-run
wizard writes an explicit `AURASCAN_AI_ENABLED` value so the user's choice is
clear. When enabled, package AI analysis may send package metadata, PKGBUILD
text, and install-script text to the configured provider. Config drift diff
review has an additional opt-in gate and sends only redacted bounded diffs.
Incident AI normally runs when the user opens an incident. A separate explicit
opt-in permits background AI only in the logged-in user service. The root boot,
weekly, and Safe Autopilot services have no network access and never load API
credentials. Incident evidence is bounded and redacted before persistence or
AI use, and `facts-only` mode omits raw evidence excerpts. See
[`docs/PRIVACY.md`](docs/PRIVACY.md) for process and storage boundaries.

Recovery AI has a separate consent bit. Neither the locally built UKI nor the
release ISO contains an API key, user config, saved WLAN profile, hostname,
home path, or incident evidence. A validated target-user provider config is
read only after target mount and network setup; an optional session key remains
in memory. Recovery AI receives the same bounded redacted/facts-only evidence
and opaque probe/action IDs as foreground incident AI.

Supported AI provider IDs are `openai`, `anthropic`, `deepseek`, `gemini`, and
`openrouter`. Provider-specific keys use `AURASCAN_OPENAI_API_KEY`,
`AURASCAN_ANTHROPIC_API_KEY`, `AURASCAN_DEEPSEEK_API_KEY`,
`AURASCAN_GEMINI_API_KEY`, or `AURASCAN_OPENROUTER_API_KEY`. Legacy
`AURASCAN_AI_KEY` remains supported for existing setups.

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
signatures when local scanners are available.

It is a review and blocking layer, not a complete endpoint security system.
Use it alongside normal Arch-family package trust practices, source review,
maintainer reputation checks, and system backups.
