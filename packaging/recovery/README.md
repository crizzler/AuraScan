# AuraScan Recovery Release Images

`build-iso.sh` creates a hybrid BIOS/UEFI recovery image from an exact clean
AuraScan commit. The version is read from that commit's Arch `PKGBUILD` and is
injected into the Archiso profile and live banner; recovery sources do not pin
an older application version.

## Build contract

Run the builder only inside a freshly provisioned, disposable, fully updated,
and externally CPU/RAM/disk-bounded Arch VM or host with no host disk or home
share. Create a fresh public clone as root, detach it at the reviewed release-
candidate commit, and run the complete build from that root-owned clone. Every
checkout path component and checkout entry must be root-owned and not
group/world writable;
symlinks, ignored files, and untracked files are refused. Do not elevate this
script from a normal user's checkout—the shell would already have read
user-mutable code before an in-script ownership check could help.

Provision the build host itself with a supported kernel and the complete
`linux-firmware` package set before starting. In particular,
`/usr/lib/firmware` must exist as root-owned host input for the exact-candidate
validation UKI; firmware packages installed later inside the Archiso image do
not satisfy that host prerequisite.

```bash
sudo -i
REVIEWED_RC_COMMIT=replace-with-the-reviewed-40-lowercase-hex-commit
[[ "$REVIEWED_RC_COMMIT" =~ ^[0-9a-f]{40}$ ]] || exit 1
CHECKOUT="/root/aurascan-recovery-build-$REVIEWED_RC_COMMIT"
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/root USER=root LOGNAME=root \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 \
  /usr/bin/git -c core.hooksPath=/dev/null -c protocol.file.allow=never \
  -c protocol.ext.allow=never clone --no-checkout \
  https://github.com/crizzler/AuraScan.git "$CHECKOUT"
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/root USER=root LOGNAME=root \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  /usr/bin/git -C "$CHECKOUT" \
  -c core.hooksPath=/dev/null checkout --detach "$REVIEWED_RC_COMMIT"
[[ "$(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/root USER=root LOGNAME=root \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 /usr/bin/git -C "$CHECKOUT" rev-parse HEAD)" == "$REVIEWED_RC_COMMIT" ]] \
  || exit 1
# EXTERNAL_ROOT_TREE_CHECK: this runs before Bash reads candidate build code.
[[ "$(/usr/bin/readlink -e -- "$CHECKOUT")" == "$CHECKOUT" ]] || exit 1
if ! UNSAFE_CHECKOUT_ENTRY="$(/usr/bin/find "$CHECKOUT" -xdev \
  \( -type l -o ! -user root -o \( ! -type l -a -perm /022 \) \) \
  -print -quit)"; then
  exit 1
fi
[[ -z "$UNSAFE_CHECKOUT_ENTRY" ]] || exit 1
BUILDER="$CHECKOUT/packaging/recovery/build-iso.sh"
[[ -f "$BUILDER" && ! -L "$BUILDER" && -x "$BUILDER" ]] || exit 1
cd "$CHECKOUT"
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/root USER=root LOGNAME=root \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
  /usr/bin/bash packaging/recovery/build-iso.sh
```

The fixed Bash path plus minimal entry environment are part of the boundary:
they keep `PATH`, `BASH_ENV`, loader variables, proxies, provider settings, and
exported shell functions out before candidate code is read. The script rejects
additional inherited variables rather than attempting to sanitize them after
the interpreter may already have acted on them.

The default output is
`/var/lib/aurascan-recovery-builder/release-$VERSION`; a new unpredictable work
directory is created beside it for every invocation. An explicit output
argument is accepted only below that root-owned, non-group/world-writable base
and must be absent or empty. The work path cannot be supplied through the
environment. The builder never deletes or searches an older work/output
directory and accepts only the exact
`aurascan-recovery-$VERSION-x86_64.iso` filename. Retained root-owned work
state is needed for release auditing and scenario tests.

The builder also prints `Trusted validation harness root` and `Private
validation attestation`. The former names the
exact retained source snapshot at
`$WORK/source-snapshot/AuraScan-$VERSION`. Run the QEMU harnesses only from
that root-owned, non-group/world-writable, symlink-free snapshot. Never run a
release gate from the normal desktop checkout: Python reads the small bootstrap
before its self-check, so the caller must establish that retained-snapshot
trust boundary first. The bootstrap then verifies itself, the root supervisor,
the selected harness, and both guards before candidate Bash starts. The
root-only attestation also binds the Secure Boot preparer, all source and built
readiness-marker units, the ISO/checksum/package-list trio, and the
exact-candidate validation UKI and sidecar by stable file identity and SHA-256.

Every subprocess receives a minimal environment. General, Instruction Guard,
incident, and recovery AI are explicitly disabled with
`AURASCAN_AI_ENABLED=0`, `AURASCAN_INSTRUCTION_AI_ENABLED=0`,
`AURASCAN_INCIDENT_AI_ENABLED=0`, and `AURASCAN_RECOVERY_AI_ENABLED=0`.
Provider, endpoint, API-key, token, proxy, dynamic-loader, Python, Git, and
user makepkg configuration variables are absent because the build uses
`env -i`, a private build home, fixed absolute basic utilities,
identity-validated native build/parser tools, and the system
`/etc/makepkg.conf`. There is no model/provider call in the build.

The builder packages the exact commit with `git archive`, stages only that
snapshot's AuraScan overlay, and refuses a changed HEAD/worktree. Before any
build it requires the exact v0.10.3 recovery-bearing, `build-required`, empty
URL/digest manifest plus `pkgrel=1` and `sha256sums=('SKIP')` in synchronized
Arch metadata. The AuraScan package build runs as a fixed unmapped numeric UID
inside a fresh network namespace with bounded runtime, output, descriptors,
processes, and file size. The desktop user cannot traverse its mode-0700
staging root. All such processes are retired before root reclaims the tree,
removes group/world write access, validates it, and copies one exact package
into the separately root-owned repository consumed by Archiso. That private
repository is inserted before every official repository, and the completed
Archiso package list must contain the exact candidate package version; an
official package with the same name therefore cannot silently replace it.

Archiso 89's known `modules.alias` defect is handled only when the installed
root-owned `/usr/bin/mkarchiso` contains one exact affected line. The builder
makes that one-line correction in root-owned work, verifies the complete
result, and runs the root-owned copy. Any other Archiso-89 shape fails closed;
no user-writable elevated copy is permitted. Newer affected implementations
also fail closed.

This boundary prevents a normal desktop user from changing the profile,
package repository, cache, or work tree between validation and root use. It is
not a full sandbox and does not make a malicious reviewed commit harmless: the
root builder, Archiso profile, recovery Python, mkosi, kernel, firmware, and
system tools remain trusted release inputs. Root compromise defeats it. Use a
disposable builder, review/authenticate the exact commit, and discard the
builder after publishing.

The completed build is rejected unless:

- exactly one correctly named ISO is produced and is strictly smaller than
  2 GiB (`2147483648` bytes is already too large for a GitHub release asset);
- its SHA-256 sidecar binds that exact basename and digest;
- its nonempty package manifest is UTF-8, bytewise sorted, and unique;
- no live mount remains below the expanded root;
- the bounded no-follow audit of the staged overlay, package build/repository
  containers, assembled ISO tree, raw ISO, and root-created expanded-filesystem
  tar stream finds no explicitly supplied private marker values, build paths,
  populated home/network state, persistent builder hostname or machine-id,
  credential assignments/known provider-token prefixes, replacement races,
  unsafe types/paths, or scan-limit failures. Normalized filesystem/tar entry
  names, link destinations, owner/group names, PAX keys/values, and strictly
  decoded padded or unpadded libarchive xattrs are included in the byte bound.
  Empty or short explicit markers and short host identities fail closed rather
  than being omitted. The auditor does not load host AuraScan/provider
  configuration or enumerate arbitrary secret stores, so this is not proof
  that every unknown or configured secret is absent. The exact source
  commit/archive remains a separately reviewed public input because its inert
  tests intentionally contain defanged private-path and credential examples.
  Initramfs and EFI files are derived inside the sanitized expanded root and
  are scanned only as bounded opaque output bytes; the audit does not
  recursively extract or interpret nested executables, filesystems, initramfs
  images, or compressed containers.

The exact package build input/output directory is included in that audit. Its
sanitized test HOME is retained only as private builder state and is not a
release artifact, so it is excluded; the complete expanded-root stream still
rejects every populated `/home` path. Standard links such as
`/var/lib/dbus/machine-id -> /etc/machine-id` are path references, not identity
bytes. Their destinations remain subject to path policy, while the actual
`/etc/machine-id` and `/etc/hostname` entries are independently checked. The
machine ID must be empty/whitespace-only or the systemd `uninitialized`
first-boot sentinel; the hostname must be exactly recovery-specific.

The release assets are an indivisible three-file set:

```text
aurascan-recovery-$VERSION-x86_64.iso
aurascan-recovery-$VERSION-x86_64.iso.sha256
aurascan-recovery-$VERSION-x86_64.iso.packages.txt
```

Local UKIs are kernel-, machine-, and Secure-Boot-key-specific validation
artifacts. The builder creates one unsigned UKI below its retained work tree
from the same committed snapshot's `create_recovery_overlay()` and
`build_uki_command()`, not from the installed AuraScan. It must be smaller than
the smoke harness's strict 512 MiB ceiling; `validate_recovery_image()` and one
runtime/output-bounded `ukify inspect` must prove the selected kernel and
recovery-service request. Hostname, machine-id, exact checkout/work paths, and
a fixed builder marker are forbidden during the validation scan. A
basename-bound SHA-256 sidecar is retained beside it, and the builder prints
the UKI path and digest for QEMU. Its private validation basename includes the
full source commit, while `SOURCE_DATE_EPOCH` is bound to that commit's time.
Test it, but never copy it into the three-file release output or publish it as
a universal release asset.

## Objective boot gates

The ISO exposes the fixed, secret-free `AURASCAN_RECOVERY_READY` serial marker
only after systemd has started the recovery service and reached the marker
unit. The smoke harnesses use a 300-second default timeout (configurable only
from 30 through 900 seconds), cap their serial log, disable networking, and
fail unless the expected journal-bound marker and positive service PID are
observed. Their line parser accepts zero, one, or two carriage returns at the
line boundary because the systemd/QEMU serial path can duplicate that
transport character; it does not strip other control bytes or accept a bare
marker:

```bash
# Copy the exact four shell assignments printed by the successful builder:
# RECOVERY_ISO=..., RECOVERY_UKI=..., RECOVERY_HARNESS_ROOT=..., and
# RECOVERY_ATTESTATION=.... Do not discover them with a wildcard.
: "${RECOVERY_ISO:?copy the exact builder assignment}"
: "${RECOVERY_UKI:?copy the exact builder assignment}"
: "${RECOVERY_HARNESS_ROOT:?copy the exact builder assignment}"
: "${RECOVERY_ATTESTATION:?copy the exact builder assignment}"
[[ "$RECOVERY_HARNESS_ROOT" == /var/lib/aurascan-recovery-builder/*/source-snapshot/AuraScan-* ]] || exit 1
RECOVERY_LAUNCHER="$RECOVERY_HARNESS_ROOT/packaging/recovery/recovery-smoke-bootstrap.py"
ROOT_SMOKE=(/usr/bin/env -i PATH=/usr/bin:/bin HOME=/root USER=root LOGNAME=root \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC /usr/bin/python3 -I -S \
  "$RECOVERY_LAUNCHER" --attestation "$RECOVERY_ATTESTATION")
"${ROOT_SMOKE[@]}" iso "$RECOVERY_ISO" bios
"${ROOT_SMOKE[@]}" iso "$RECOVERY_ISO" uefi \
  --firmware-code /usr/share/edk2/x64/OVMF_CODE.4m.fd \
  --firmware-vars /usr/share/edk2/x64/OVMF_VARS.4m.fd
"${ROOT_SMOKE[@]}" uki "$RECOVERY_UKI" uefi \
  --firmware-code /usr/share/edk2/x64/OVMF_CODE.4m.fd \
  --firmware-vars /usr/share/edk2/x64/OVMF_VARS.4m.fd
```

Start these commands as root. The launcher verifies the private root-owned
receipt and hashes the selected harness and guards before Bash reads candidate
code. It verifies the fixed OVMF files against an unaltered `edk2-ovmf`
package, snapshots all run inputs below one fresh retained-work run root, then
runs Bash/QEMU as an unassigned UID with no capabilities or supplementary
groups in a fresh network namespace. QEMU uses TCG plus its deny sandbox; the
root supervisor bounds output/runtime, retires surviving isolated-UID
processes, removes only that exact run root, and writes a private `PASS` receipt
only afterward. Exit zero or a printed success sentence is insufficient: the
supervisor also requires a strict private outcome document and independently
rehashes bounded private serial-log snapshots proving the exact readiness and,
for Secure Boot, unsigned-rejection controls. The receipt retains only their
roles, outcomes, sizes, and SHA-256 values, not raw serial text. A failed,
interrupted, malformed, or incomplete launch writes no `PASS` result.

The launcher supplies one exact attested private runtime as `TMPDIR`. Every
nested minimal-environment wrapper must preserve that value unchanged when it
invokes a guard; it must not fall back to a system temporary directory or
derive a replacement. The harness writes its strict outcome only to the fixed
launcher-expected filename below that runtime, so losing this binding is a
failed gate even if QEMU reached the readiness marker.

Secure Boot is a distinct two-control test. It refuses to run without a
signature-bearing UKI, Secure Boot OVMF code, and a vars template containing
only disposable enrolled test keys. The harness derives an unsigned control by
removing and verifying the signed input's signature table while preserving its
payload binding. Passing requires independent mutable copies of that immutable
template to reject the derived unsigned control and boot the signed UKI through
the readiness marker; firmware-mutated state is never reused between controls:

Signature-table helpers operate only on private, size-validated UKI copies.
Their elapsed time and combined stdout/stderr are capped independently from
artifact mutation. The file-size resource ceiling must allow a complete UKI
rewrite up to the separately enforced artifact-size limit; the smaller
diagnostic-output budget must never be reused as that ceiling. Each resulting
file is revalidated before it becomes a boot-gate input.

```bash
RECOVERY_PREPARER="$RECOVERY_HARNESS_ROOT/packaging/recovery/prepare-secure-boot.py"
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/root USER=root LOGNAME=root \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC /usr/bin/python3 -I -S \
  "$RECOVERY_PREPARER" --attestation "$RECOVERY_ATTESTATION"
# Copy the exact four shell assignments printed by that successful preparation.
: "${SECURE_PREPARATION_RECEIPT:?copy the exact preparation assignment}"
: "${SIGNED_RECOVERY_UKI:?copy the exact preparation assignment}"
: "${PREPARED_SECURE_CODE:?copy the exact preparation assignment}"
: "${PREPARED_ENROLLED_VARS:?copy the exact preparation assignment}"
"${ROOT_SMOKE[@]}" --secure-preparation-receipt "$SECURE_PREPARATION_RECEIPT" \
  uki "$SIGNED_RECOVERY_UKI" secure-boot \
  --firmware-code "$PREPARED_SECURE_CODE" \
  --firmware-vars "$PREPARED_ENROLLED_VARS"
```

The Secure Boot preparation receipt must use AuraScan's strict preparation
schema and bind the same base build receipt and unsigned validation UKI. The
launcher rejects arbitrary replacements, requires root-reclaimed signed UKI,
sidecar, secure-code, and enrolled-vars outputs, and independently checks that
the prepared secure-code bytes equal the clean packaged OVMF input. After
signature removal the harness requires the unsigned digest to equal the base
builder attestation's validation-UKI digest before either VM can run.

These markers prove the stated boot/service boundary, not storage recovery.
Complete the encrypted Btrfs, ext4/LVM, network/offline, interrupted-package,
snapshot-confirmation, and unknown-bootloader-refusal scenarios separately and
record their expected and observed outcomes using
[`SCENARIO_VALIDATION.md`](SCENARIO_VALIDATION.md). Never summarize an
interactive or unrun scenario as passing.

## Recovery-bearing release sequence

1. Commit a clean release candidate with the application/Arch version updated,
   Arch source checksum temporarily `SKIP`, and the recovery ISO manifest in
   explicit build-required placeholder state with no digest.
2. Build from that exact commit. Boot-test the ISO in BIOS and ordinary UEFI;
   test the local UKI in ordinary and disposable-key Secure Boot modes; then run
   and record the deterministic and booted recovery scenarios in
   `SCENARIO_VALIDATION.md` plus the bounded artifact/privacy audit. Describe
   that audit by its actual marker and path coverage, not as proof that no
   unknown secret exists. Record the full release-candidate commit printed by
   the builder together with the ISO and validation-UKI digests.
3. Pin the exact ISO URL, filename, version, release date, and SHA-256 in the host
   manifest and commit it. The ISO intentionally retains the clean candidate's
   placeholder manifest, avoiding a self-referential image hash. Do not rebuild
   or relabel the ISO after this pin; restrict the final pre-tag delta to the
   manifest and bounded release evidence, then rerun the source/package gates
   and prove the retained digest still names the tested RC bytes.
4. Create the immutable annotated tag and a **draft** GitHub release. Upload
   exactly the ISO, checksum sidecar, and sorted package list. Download or query
   the draft assets and verify all three remote names, sizes, and SHA-256 values
   against the locally tested files before publishing the release.
5. Hash the exact public tag archive, finalize `PKGBUILD`/`.SRCINFO`, publish
   that metadata commit, and update the separate AUR clone without rewriting
   the tag or force-pushing.

The release gate rejects the known private paths and supplied marker values
described above; it does not prove the absence of every possible secret inside
an opaque nested image. A failed, incomplete, or skipped required build, boot,
scenario, or bounded privacy gate makes the candidate ineligible for a
recovery-bearing release; an explicitly optional platform scenario may be
omitted only when the release record and public claims both say it was not run.
