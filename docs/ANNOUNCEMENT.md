# AuraScan Announcement Draft

Use this as a starting point for CachyOS, Arch-adjacent, Reddit, Mastodon,
Matrix, or Discord posts. Keep the tone transparent: AuraScan reduces risk, but
it does not prove package safety.

## Short Post

AuraScan is an early developer-preview safety layer for Arch Linux, CachyOS, and
AUR workflows.

It can scan PKGBUILDs and package archives, wrap makepkg before build scripts
run, preview risky upgrade conditions with `aurascan upgrade --dry-run`, and
help explain `.pacnew`/`.pacsave` config drift with backups before applying
safe fixes.

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
```

Important limits: AuraScan is a developer preview. A clean report is not proof
that a package or upgrade is safe. Network AI is optional and advisory. The
project is looking for testing, packaging feedback, and real-world false
positive reports.

## Longer Post

I am building AuraScan, a security-focused assistant for Arch/CachyOS package
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

What I would value most:

- CachyOS/Arch users testing dry-run output.
- Packaging feedback for a future AUR package.
- False positive reports from real PKGBUILDs and upgrades.
- Suggestions for making the terminal UX friendlier for non-expert Linux users.

Repo: https://github.com/crizzler/AuraScan

This is not a guarantee layer or a replacement for backups. It is an early
attempt to make the dangerous parts of package management more visible before
the user has to become an Arch expert.
