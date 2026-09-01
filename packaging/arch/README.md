# Arch Packaging Notes

This directory contains the Arch/AUR packaging recipe for AuraScan. It is the
package-manager-owned install path for public release builds, not a claim that
the package is accepted into the official repositories.

Before publishing to the AUR, verify the checksum against the public GitHub
release/tag source archive, then regenerate `.SRCINFO` from the final PKGBUILD:

```bash
AURASCAN_PACKAGE_BUILD_HOME=/private/empty/aurascan-package-build-home
test -d "$AURASCAN_PACKAGE_BUILD_HOME" && \
  test -z "$(/usr/bin/find "$AURASCAN_PACKAGE_BUILD_HOME" -mindepth 1 -print -quit)"
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$AURASCAN_PACKAGE_BUILD_HOME" \
  USER=aurascan-release LOGNAME=aurascan-release LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  TZ=UTC AURASCAN_AI_ENABLED=0 AURASCAN_INSTRUCTION_AI_ENABLED=0 \
  AURASCAN_INCIDENT_AI_ENABLED=0 AURASCAN_RECOVERY_AI_ENABLED=0 \
  /usr/bin/updpkgsums
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$AURASCAN_PACKAGE_BUILD_HOME" \
  USER=aurascan-release LOGNAME=aurascan-release LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  TZ=UTC AURASCAN_AI_ENABLED=0 AURASCAN_INSTRUCTION_AI_ENABLED=0 \
  AURASCAN_INCIDENT_AI_ENABLED=0 AURASCAN_RECOVERY_AI_ENABLED=0 \
  /usr/bin/makepkg --config /etc/makepkg.conf --printsrcinfo > .SRCINFO
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$AURASCAN_PACKAGE_BUILD_HOME" \
  USER=aurascan-release LOGNAME=aurascan-release LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  TZ=UTC AURASCAN_AI_ENABLED=0 AURASCAN_INSTRUCTION_AI_ENABLED=0 \
  AURASCAN_INCIDENT_AI_ENABLED=0 AURASCAN_RECOVERY_AI_ENABLED=0 \
  /usr/bin/makepkg --config /etc/makepkg.conf -Ccsr
```

Create the private build home as a fresh mode-`0700` directory and remove it
afterward; do not reuse a normal user home. The empty environment matters even
for `updpkgsums`, because it invokes `makepkg` internally. It excludes exported
shell functions, loader/Python variables, proxies, destination/config
overrides, provider credentials, and a user `makepkg.conf`, while the fixed
PATH prevents a local `aurascan-makepkg` wrapper from contaminating metadata.
General, Instruction Guard, Incident, and Recovery AI are all forced to zero.

The public AUR package is a separate Git repository and uses SSH-key
authentication rather than the GitHub remote:

```bash
/usr/bin/git clone ssh://aur@aur.archlinux.org/aurascan.git
/usr/bin/git push origin master
```

These are illustrative transport commands, not an identity shortcut. Before
using them, validate the absolute Git/SSH tools, expected AUR host key and SSH
account, remote URL, branch, and remote head as required by the release
checklist. Never force-push.

Publish only after the matching GitHub tag is public and this recipe contains
its fixed archive checksum. Preserve the AUR repository's maintainer/SPDX
header, `.gitignore`, and 0BSD packaging `LICENSE`; do not replace those files
with the upstream repository variants. Review the complete staged AUR diff and
generated `.SRCINFO` before pushing. See the ArchWiki
[AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines).

The package source URL is the tagged GitHub release archive:

```text
https://github.com/crizzler/AuraScan/archive/refs/tags/v${pkgver}.tar.gz
```

The package version must match `pyproject.toml`, and `.SRCINFO` must be
regenerated from the final PKGBUILD before publishing.

The AUR package contains the strict recovery manifest and optional host-side
recovery integration; it does not contain the large release ISO or a universal
UKI. Package install/upgrade never downloads or builds an image, writes the
ESP, or enables a recovery entry. User-facing recovery capabilities are split
across the `mkosi`, `systemd-ukify`, `sbctl`, networking, storage, and
filesystem `optdepends` in `PKGBUILD`. Archiso, QEMU, OVMF, `sbsigntools`, and
`virt-firmware` are maintainer validation dependencies, not requirements for a
normal AuraScan install.

The release pacman hook is `packaging/arch/aurascan.hook`. It is intended to be
installed by an Arch package to:

```text
/usr/share/libalpm/hooks/aurascan.hook
```

The hook calls the installed executable:

```text
/usr/bin/aurascan
```

It must not point at a source checkout, a virtual environment, or a developer
home directory. A pip install does not install pacman hooks. Pacman hooks
require root/package-manager installation, and uninstalling the Arch package
should remove the hook with the package files.

The packaging skeleton also includes `aurascan.install`. It is advisory text only:
it prints first-use guidance for `aurascan init`, `aurascan doctor`, and
`aurascan-makepkg`. It must not prompt, run AuraScan, request API keys, write
configuration, install hooks manually, contact the network, run makepkg, or
inspect packages during package install or upgrade.

Manual hook installation is possible by copying a hook to
`/etc/pacman.d/hooks/`, but users should do this carefully and remove it if
AuraScan is uninstalled. A hook left behind that points to a missing executable
can break pacman transactions.

The pacman hook scans built package archives before pacman transactions. It
does not protect against malicious PKGBUILD build-time logic, because that code
can run earlier during makepkg. Use `aurascan-makepkg` for pre-build AUR
protection.

The hook remains conservative:

- it does not pass `--scan-context update`;
- it does not enable `--update-scan-policy smart`;
- it does not run `--deep-static`;
- it does not fetch sources, clone repositories, fetch PGP keys, or run GPG.

Optional external tools:

- `clamscan`: AV signature scanning when available;
- `gpg`: explicit deep-static signature verification outside the default hook;
- `makepkg`: wrapper workflows through `aurascan-makepkg`;
- `pacman`/`vercmp`: local package DB context proof for explicit `--scan-context auto` flows.
- `python-pyqt6`: optional AuraScan Updater tray applet.
- `libnotify`: optional generic Agent Instruction Guard desktop notifications.
- `pacman-contrib`: bounded `paccache` cleanup for a proven disk-exhaustion
  incident.

The package installs the reusable `aurascan-updater.desktop` launcher plus
normal, maintenance-due, attention, and critical tray icons.
Per-user autostart remains controlled by the wizard or `aurascan updater
--install-autostart`; package install must not enable it automatically.

The package also installs the root boot/weekly collectors, the disabled
per-user incident AI assistant timer, the offline Safe Autopilot oneshot, and
tmpfiles rules. Every unit remains disabled or inert after installation. Users
opt into collection through `aurascan init --enable-incident-monitor`, opt into
logged-in AI separately, and must separately set the root repair policy to
`safe`. Package installation must not call `systemctl enable`, scan logs,
contact AI, or perform repairs.

The root collectors and Safe Autopilot have no network access. The user AI
service has network access but no privilege escalation or writable system
paths. It may make at most two bounded requests, run allowlisted read-only
diagnostic probes, and prepare a private repair plan for foreground
confirmation; it cannot invoke repairs or `sudo`. Safe Autopilot accepts only
stale pacman-lock and verified mirrorlist
recovery, never loads API credentials, and defaults to `off`. Public status and
markers contain only non-sensitive timing, category, UID-scope, and coarse
repair state; evidence and AI output remain private.

The package also installs
`aurascan-instruction-monitor.service`/`.timer` and
`aurascan-instruction-assistant.service`/`.timer` as disabled user units. Users
may opt into the deterministic monitor with `aurascan init
--enable-instruction-monitor` or `aurascan instruction-audit
--enable-monitor`. It runs after login and every five minutes with network
access disabled, a read-only home, private writable state, low resource
priority, and AI credentials removed. Finding a suspicious file is recorded as
a successful service run, not a systemd unit crash.

Instruction Guard AI is a separate opt-in through `aurascan init
--enable-instruction-ai` or `aurascan instruction-audit --enable-ai`. Its
network-capable unprivileged assistant processes at most one private redacted
job per run using the configured provider, and it cannot lower deterministic
severity or trust changed content. Package installation must not enable either
timer, scan a home directory, contact a provider, or create Instruction Guard
state. Missing `notify-send` affects only desktop notification delivery; CLI
review state and the tray remain available.

Current hook failure behavior:

- Missing package archive targets are reported as warnings and do not block by
  themselves.
- If AuraScan finds a blocking issue, it exits non-zero and pacman should stop
  the transaction.
- If `clamscan` is unavailable, AuraScan prints a warning and skips AV scanning.
- If `/usr/bin/aurascan` is missing, pacman cannot run the hook command; recover
  by reinstalling AuraScan or removing the stale hook from the hook directory.
- Scanner errors that produce blocking findings block. Non-blocking unavailable
  optional tools are reported and the conservative scan continues.
