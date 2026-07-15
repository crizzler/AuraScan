# AuraScan Announcement Draft

Use this as a starting point for Arch-family communities, Reddit, Mastodon,
Matrix, or Discord posts. Keep the tone transparent: AuraScan reduces risk, but
it does not prove package safety.

## Short Post

AuraScan is an early developer-preview safety layer for Arch Linux,
EndeavourOS, Manjaro, CachyOS, and AUR workflows.

It can scan PKGBUILDs and package archives, wrap makepkg before build scripts
run, preview risky upgrade conditions with `aurascan upgrade --dry-run`, and
help explain `.pacnew`/`.pacsave` config drift with backups before applying
safe fixes. The new `aurascan incidents --dry-run` command can also inspect
bounded crash evidence and explain likely system or application failures.
An optional weekly local scan can also catch recoverable errors during long
uptime. Separately opted-in logged-in AI can select bounded read-only local
diagnostic probes, then explain and prioritize the independently verified
repair plan. The offline Safe Autopilot still handles only reversible
lock/mirror repairs.

The v0.6 work adds an optional `AuraScan Recovery` boot environment. It starts
offline diagnostics when the installed OS cannot boot, helps connect Ethernet
or WPA2/WPA3 Wi-Fi, and uses separately consented AI only to select opaque local
checks and prioritize independently verified repairs. Internal UEFI recovery is
installed only on request; a hybrid BIOS/UEFI USB image is the fallback.

The new `aurascan upgrade` flow is designed as a native-feeling upgrade front
door: it previews repo and AUR updates, checks kernel/module/initramfs/boot
space/ignored-package/config-drift risks, optionally asks configured AI to
raise risk severity, then hands off to pacman, paru, yay, or Shelly.

Repo: https://github.com/crizzler/AuraScan

Try:

```bash
python -m pip install -e ".[test]"
python -m aurascan init
python -m aurascan upgrade --dry-run
python -m aurascan config-drift --dry-run
python -m aurascan incidents --dry-run --no-ai
python -m aurascan recovery --status
```

Important limits: AuraScan is a developer preview. A clean report is not proof
that a package or upgrade is safe. Network AI is optional and advisory. The
project is looking for testing, packaging feedback, and real-world false
positive reports.

## Longer Post

I am building AuraScan, a security-focused assistant for Arch-family package
workflows.

The original goal was to make AUR package review less easy to skip. AuraScan
looks for risky PKGBUILD patterns, install hooks, unsafe source/archive
behavior, checksum/signature drift, local history changes, and optional ClamAV
or AI signals. It can also be used through `aurascan-makepkg` so the review
happens before makepkg runs package functions.

The newest work adds upgrade safety helpers:

- `aurascan upgrade --dry-run` previews repo and AUR updates.
- It checks low `/boot` or root space, kernel/module rebuild risk, ignored
  packages, initramfs/bootloader-sensitive updates, replacements/conflicts,
  foreign package risk, and `.pacnew`/`.pacsave` drift.
- It supports pacman-only upgrades plus paru, yay, and Shelly handoff.
- AI review is optional and raise-only. It can add caution, but it cannot mark
  an upgrade safe or suppress deterministic findings.
- `aurascan config-drift --dry-run` explains config drift and prepares safe
  fixes with backups before applying.
- `aurascan incidents --dry-run` examines bounded journal, coredump, pstore,
  package, and module evidence. Its two-pass AI planner may choose only known
  probe IDs and recommend only verified action IDs; repair commands still come
  exclusively from AuraScan's allowlist.
- The optional root collectors are disabled until the user enables them and
  perform no AI requests or repairs themselves. Background AI is a separate
  per-user opt-in that may prepare a private plan but has no execution authority.
- Safe Autopilot is separately disabled by default, stays offline, and permits
  only deterministic stale pacman-lock or verified mirrorlist restoration.
- Enabling incident monitoring also enables a low-priority weekly current-boot
  scan. Clean runs stay silent; the tray changes state for overdue or
  unreviewed maintenance findings.
- The tray exposes one guided **Resolve System Findings** action. Verified
  AuraScan repairs can be confirmed there; historical findings without a safe
  repair are explained and acknowledged without running AI-generated commands.
- The optional tray applet targets KDE first, should work on common
  tray-capable desktops, and may need AppIndicator/status-notifier support on
  GNOME.
- `aurascan recovery` can build an optional local UKI, add an AuraScan-owned
  Limine/systemd-boot/GRUB entry, or write a verified hybrid recovery ISO to an
  eligible removable whole disk. Package installation never changes the ESP.
- Recovery supports bounded Arch-family target discovery across Btrfs, ext4,
  XFS, LUKS2, LVM2, and mdraid, with offline package/boot diagnostics first.
- Recovery AI has separate consent, never receives executable targets, and
  falls back cleanly when networking or a provider is unavailable. Snapshot
  restore and bootloader reinstall require exact typed confirmations.

What I would value most:

- Arch, EndeavourOS, Manjaro, and CachyOS users testing dry-run output.
- Packaging feedback for a future AUR package.
- False positive reports from real PKGBUILDs and upgrades.
- Suggestions for making the terminal UX friendlier for non-expert Linux users.

Repo: https://github.com/crizzler/AuraScan

This is not a guarantee layer or a replacement for backups. Incident recovery
does not automate filesystem repair, partition changes, Secure Boot key
enrollment, arbitrary AI commands, or reboots. Bootloader recovery is available
only for a positively detected loader/ESP after a separate typed confirmation.
It is an early attempt to make dangerous package and recovery work
more visible before the user has to become an Arch expert.
