# Arch Packaging Notes

This directory contains the Arch/AUR packaging recipe for AuraScan. It is the
package-manager-owned install path for public release builds, not a claim that
the package is accepted into the official repositories.

Before publishing to the AUR, verify the checksum against the public GitHub
release/tag source archive, then regenerate `.SRCINFO` from the final PKGBUILD:

```bash
updpkgsums
/usr/bin/makepkg --printsrcinfo > .SRCINFO
/usr/bin/makepkg -Ccsr
```

Use `/usr/bin/makepkg` here so a local `aurascan-makepkg` wrapper cannot write
diagnostic output into `.SRCINFO`.

The package source URL is the tagged GitHub release archive:

```text
https://github.com/crizzler/AuraScan/archive/refs/tags/v${pkgver}.tar.gz
```

The package version must match `pyproject.toml`, and `.SRCINFO` must be
regenerated from the final PKGBUILD before publishing.

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
