# Isolated AUR build backend — design and boundaries

Status: first slice implemented (`AURASCAN_AUR_SANDBOX=devtools`). This
document describes the threat model, the invariants the implementation must
keep, and the parts that deliberately remain out of scope.

## Why this exists

The `UPG-AUR-BUILD-UNSCANNED` blocker does not say that AUR packages are
malicious. It says AuraScan cannot prove that an AUR helper will route every
planned source build through `aurascan-makepkg`. That is a broken trust chain:
the helper still runs `makepkg` on the daily system, after preflight.

The helper cannot repair the chain. Shelly, for example, exposes no
build-command setting; its user configuration contains
`AurInstallUseChroot` and update-check booleans, but nothing that lets AuraScan
substitute its wrapper. Adding a sandbox therefore means removing the helper
from the AUR build path, not teaching the helper to use one.

## What the sandbox changes

When the route is enabled explicitly (`AURASCAN_AUR_SANDBOX=devtools` or
`--aur-sandbox devtools`) or accepted from the interactive offer described
below, and the backend is available, the upgrade flow:

1. replans the transaction with `--aur-helper none`;
2. applies and verifies the repository transaction through the trusted
   `sudo`/`pacman` handoff;
3. downloads each pending AUR update with the trusted Git boundary;
4. reviews it through `aurascan-makepkg --aurascan-scan-only`;
5. builds it inside a private copy of a root-owned `extra-x86_64` devtools
   chroot;
6. requires every produced package archive to embed the scanned install hook;
7. scans every produced archive with the package analyzers;
8. installs exactly the scanned archives through trusted `sudo pacman -U`.

The `UPG-AUR-BUILD-SANDBOXED` finding (MEDIUM) replaces the CRITICAL blocker
only when steps 1–8 are actually available. If the backend is missing, unsafe,
or misconfigured, the original CRITICAL blocker remains and the helper is
still never asked to build AUR packages.

## What the sandbox buys

- Build functions, `prepare()`, `check()`, source downloads, and anything they
  spawn run outside the caller's home, SSH agent, browser profile, AuraScan
  state, and pacman keyrings.
- The reviewed checkout is copied into a private tree. The original checkout
  is not modified, and generated `src`/`pkg` and VCS internals are not copied.
- Artifacts are hash-bound before installation, so the package that is
  installed is the package that was scanned.
- The install hook embedded in the built package must equal the hook bytes
  that were scanned. A mismatch is a hard stop.

## What the sandbox does not buy

- It is not a proof that a package is safe. A single build shows what that
  build did in that environment; runtime behavior on the target can differ.
- A devtools chroot shares the host kernel. A kernel bug is an escape. If
  stronger isolation is required, use a disposable VM.
- `.INSTALL` hooks still execute as root on the host at installation time.
  The existing deterministic hook scan and the packaged-hook byte comparison
  remain mandatory.
- The base chroot is trusted infrastructure. AuraScan verifies that the chroot
  path exists, is a real directory, is root-owned, and is not group/world
  writable. It cannot prove that the base was never modified by root.
- Network access is required to fetch sources and dependencies. The build can
  reach whatever the chroot network can reach; the isolation protects the
  host filesystem and credentials, not the network.
- AUR build dependencies are built first through the same reviewed sandbox
  route, bounded by the existing dependency-chain cap. A dependency cycle, a
  chain that exceeds the cap, or a dependency that cannot be resolved stops
  the route before the parent build.

## Invariants

- Explicit consent only. The configured default is `off`; no package script,
  AI response, or helper configuration can enable it automatically. An
  interactive upgrade may offer the sandbox as the default continuation after
  showing the blocker and the risk; pressing Enter or answering `s` is the
  explicit per-run consent, and declining keeps the hard stop.
- Fixed absolute tools. `arch-nspawn`, `mkarchroot`, `sudo`, `cp`, and `rm`
  are captured as root-owned, non-writable, non-symlink identities and
  revalidated before the build. The standard `extra-x86_64-build` entry point
  is not used: it is a symlink to `archbuild`, whose `makechrootpkg` path
  hard-codes `--skipinteg`. AuraScan builds through `arch-nspawn` directly so
  checksums and signatures stay enforced.
- No host mounts. The build copy lives under a private `0700` tree; the
  environment is reduced to `PATH=/usr/bin:/bin`, a private `HOME` and
  `TMPDIR`, fixed locale/timezone, and `USER`/`LOGNAME`/`TERM`.
- Bounded tree and artifacts: 20,000 entries, 4 GiB copied input, 16 archives,
  8 GiB per archive, 12 GiB total.
- No package-controlled shell text. Host-side commands are argument vectors.
  Inside the chroot, a fixed, bounded Bash script creates the build user and
  execs `makepkg`; it never evaluates checkout text.
- Fail closed. A missing tool, unsafe chroot, failed build, timeout, missing
  fresh archive, hook mismatch, or blocked package scan prevents installation.
- No safety claims. The report says the build happened in an isolated backend;
  it never says the package is safe, clean, trusted, or approved.

## Configuration

| Setting | Values | Default |
| --- | --- | --- |
| `AURASCAN_AUR_SANDBOX` | `off`, `devtools` | `off` |
| `AURASCAN_AUR_SANDBOX_WORK_ROOT` | absolute directory | `/var/tmp` |
| `aurascan upgrade --aur-sandbox` | `off`, `devtools` | config value |

In an interactive upgrade, when the configured value is `off` and the backend
is available, the AUR-build prompt offers the sandbox as its default choice;
the other choices are repository-only and keep-blocked. `--yes`, `--json`, and
dry runs keep the original hard stop. The base chroot is created once, outside
AuraScan, with the documented
`mkarchroot` command; AuraScan refuses to start a build without it. Each build
copies the base into a private tree (`cp -a --reflink=auto`), uses a private
package cache under that tree, and removes the whole tree afterwards. The host
pacman cache is never bind-mounted.

## One-time setup

Create the base chroot once as root; AuraScan never creates it during an
upgrade:

```bash
sudo /usr/bin/mkarchroot \
  -C /usr/share/devtools/pacman.conf.d/multilib.conf \
  -M /usr/share/devtools/makepkg.conf.d/x86_64.conf \
  /var/lib/archbuild/extra-x86_64/root base-devel multilib-devel
```

Keeping the base current is the operator's responsibility. AuraScan verifies
that the path is a real root-owned directory with a `.arch-chroot` marker and
that the devtools configuration files are root-owned and non-writable; it does
not prove the base was never modified by root. The `multilib.conf` profile is
used so `lib32-*` AUR packages can install their repository dependencies; a
base created from the older `extra.conf` profile still works for core/extra,
but `multilib-devel` should be installed in it before building 32-bit
packages.

AuraScan does not update the base automatically. Refresh it periodically
before building:

```bash
sudo /usr/bin/arch-nspawn \
  -C /usr/share/devtools/pacman.conf.d/multilib.conf \
  -M /usr/share/devtools/makepkg.conf.d/x86_64.conf \
  /var/lib/archbuild/extra-x86_64/root pacman -Syuu --noconfirm
```

## Remaining work

- A rootless `podman` backend for hosts without devtools.
- A disposable KVM/microVM backend for deliberately hostile packages.
- Automated base-chroot refresh and verification (the current slice documents
  the manual refresh command but does not run it).
- Artifact retention policy for build-only invocations (the current slice
  keeps the private tree only when `--install` was not requested).
