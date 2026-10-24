# Desktop Packaging Notes

This directory contains the reference Arch/AUR recipe for the optional desktop
evidence console. It is a separate package from `aurascan`: the scanner stays
`arch=('any')` and standard-library-only Python, and the desktop package adds
the Electron runtime, the built renderer, the launcher, the desktop entry, and
the icon.

**Not published.** Do not push this recipe to the AUR until:

1. an AuraScan release ships `aurascan ui` (the shell reads its snapshot
   contract), and
2. the desktop shell has passed the same review bar as the scanner: visible
   window test, packaging test in a clean chroot, and a release-note entry.

## What the package installs

| Path | Content |
| --- | --- |
| `/usr/bin/aurascan-desktop` | launcher that runs `/usr/bin/electron /usr/lib/aurascan-desktop` |
| `/usr/lib/aurascan-desktop/electron/` | hardened main process, preload bridge, fixed argv helpers |
| `/usr/lib/aurascan-desktop/dist/` | built renderer bundle |
| `/usr/lib/aurascan-desktop/package.json` | runtime manifest with the Electron entry point |
| `/usr/share/applications/aurascan-desktop.desktop` | desktop entry |
| `/usr/share/icons/hicolor/scalable/apps/aurascan-desktop.svg` | icon |

## Build requirements

- `nodejs` and `npm` at build time. `npm ci` needs registry access; the
  committed `desktop/package-lock.json` pins every dependency.
- `ELECTRON_SKIP_BINARY_DOWNLOAD=1` is set during the build so the system
  `electron` package provides the runtime instead of a second copy.
- `depends=('aurascan' 'electron')`. The recipe does not pin an Electron release
  series; revisit that when a specific version becomes compatibility-relevant.

## Validation before publishing

```bash
/usr/bin/bash -n packaging/desktop/PKGBUILD
/usr/bin/desktop-file-validate packaging/desktop/aurascan-desktop.desktop

# Clean chroot, no host home, AI disabled, fixed PATH:
/usr/bin/makepkg --printsrcinfo > .SRCINFO
```

Never install or run the built package as part of validation on a machine that
matters: the shell starts the scanner, and the scanner's own packaging rules
still apply. A disposable Arch environment is the documented place for that
test.
