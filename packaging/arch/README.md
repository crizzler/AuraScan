# Arch Packaging Notes

This directory is a release-packaging skeleton for AuraScan. It is not a claim
that the package is ready for the official repositories or the AUR as-is.

Before publishing to the AUR, replace `sha256sums=('SKIP')` in `PKGBUILD` with
the checksum generated from the public GitHub release/tag source archive, then
generate `.SRCINFO` from the final PKGBUILD:

```bash
updpkgsums
makepkg --printsrcinfo > .SRCINFO
makepkg -Ccsr
```

The project URL is:

```text
https://github.com/crizzler/AuraScan
```

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
