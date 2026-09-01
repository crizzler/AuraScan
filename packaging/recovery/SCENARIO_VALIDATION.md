# Recovery Scenario Validation

This is the repeatable validation procedure and release-record template for
an AuraScan recovery-bearing release. It deliberately separates deterministic
fixture tests from an actual booted ISO or UKI. A unit test passing is never
evidence that a candidate image booted, discovered a real storage stack, used a
network device, or completed and rolled back a repair.

Copy the status tables into the private release evidence record and start every
row as `NOT RUN`. Change a row to `PASS` or `FAIL` only after running it against
the exact candidate commit and digest. Retain the command, UTC time, tool and
firmware versions, exit status, and bounded serial/report output. Do not put
passwords, Wi-Fi material, host paths, machine identity, or recovery evidence
in a public release note.

## Candidate identity

Record these values before any validation:

```bash
/usr/bin/git status --porcelain=v1 --untracked-files=all
/usr/bin/git rev-parse --verify 'HEAD^{commit}'
(cd -- "$(/usr/bin/dirname -- "$RECOVERY_ISO")" && \
  /usr/bin/sha256sum --check -- \
    "$(/usr/bin/basename -- "$RECOVERY_ISO").sha256")
/usr/bin/sha256sum -- "$RECOVERY_ISO" "$RECOVERY_ISO.sha256" \
  "$RECOVERY_ISO.packages.txt"
/usr/bin/stat -c '%n %s bytes mode=%a owner=%u:%g' -- \
  "$RECOVERY_ISO" "$RECOVERY_ISO.sha256" "$RECOVERY_ISO.packages.txt"
```

The worktree must be clean, the commit must remain unchanged for every row,
the ISO digest must match its exact-name sidecar, and the ISO must be strictly
smaller than 2 GiB. Re-run the identity check after validation. A changed
candidate invalidates earlier results.

## Automated deterministic fixtures

Run the local fixtures with every AI mode disabled:

```bash
AURASCAN_AI_ENABLED=0 \
AURASCAN_INSTRUCTION_AI_ENABLED=0 \
AURASCAN_INCIDENT_AI_ENABLED=0 \
AURASCAN_RECOVERY_AI_ENABLED=0 \
  .venv/bin/python -m pytest -q \
    tests/test_recovery.py \
    tests/test_recovery_network.py \
    tests/test_recovery_boot.py \
    tests/test_recovery_packaging.py \
    tests/test_recovery_build_pipeline.py \
    tests/test_recovery_iso_manifest.py
```

Expected result: pytest exits `0` with no skipped or failed required test. The
fixtures use temporary roots and mocked subprocesses. They verify parser,
policy, refusal, confirmation, command-construction, rollback, packaging, and
artifact-audit logic; they do not start QEMU, unlock a real LUKS volume, modify
a bootloader, contact a provider, or prove a built image contains the tested
code.

For a focused failure investigation, the evidence families are reproducible as
follows:

| Family | Focused deterministic command | Expected outcome |
| --- | --- | --- |
| Storage | `.venv/bin/python -m pytest -q tests/test_recovery.py -k 'target_candidate or lvm_discovery or luks_target or no_replay or unknown_filesystem'` | Read-only discovery/mount controls and refusal paths pass using temporary fixtures. |
| Network | `.venv/bin/python -m pytest -q tests/test_recovery_network.py tests/test_recovery.py -k 'wifi or network_dependent or offline_ai'` | Secrets stay out of argv/state, supported modes parse, and offline deterministic fallback remains available. |
| Repair | `.venv/bin/python -m pytest -q tests/test_recovery.py -k 'interrupted_transaction or repo_repair or exact_signed_cached_reinstall or pacman_transaction'` | Only bounded, signature-gated fixture repairs become eligible. |
| Rollback | `.venv/bin/python -m pytest -q tests/test_recovery.py -k 'snapshot_restore or failed_initramfs'` | Snapshot proof is mandatory and a failed initramfs fixture restores its prior image set. |
| Bootloader | `.venv/bin/python -m pytest -q tests/test_recovery_boot.py tests/test_recovery.py -k 'bootloader or limine or grub'` | Ambiguous/unknown loaders refuse action; generated recipes avoid firmware-variable mutation and preserve confirmation boundaries. |

Record the deterministic suite separately:

| Gate | Candidate commit | UTC time | Result | Evidence location |
| --- | --- | --- | --- | --- |
| Deterministic recovery fixtures | — | — | NOT RUN | — |

## Actual ISO and UKI boot gates

These commands run the exact built artifact. The ISO harness disables network
devices, caps serial output, and succeeds only after the recovery service emits
its fixed readiness marker. Set `RECOVERY_HARNESS_ROOT` to the exact `Trusted
validation harness root` printed by the builder. It must be the retained
root-owned, non-group/world-writable, symlink-free source snapshot, not the
user-writable desktop checkout. Python reads the small bootstrap before its
self-check, so selecting that trusted path is an external prerequisite. The
bootstrap then verifies itself, the root supervisor, selected harness, and both
guards against the private receipt before candidate Bash can source anything.

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
RECOVERY_PREPARER="$RECOVERY_HARNESS_ROOT/packaging/recovery/prepare-secure-boot.py"
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/root USER=root LOGNAME=root \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC /usr/bin/python3 -I -S \
  "$RECOVERY_PREPARER" --attestation "$RECOVERY_ATTESTATION"
# Bind the following variables to the exact four paths printed from this fresh
# preparation before invoking the Secure Boot smoke run.
: "${SECURE_PREPARATION_RECEIPT:?copy the exact preparation assignment}"
: "${SIGNED_RECOVERY_UKI:?copy the exact preparation assignment}"
: "${PREPARED_SECURE_CODE:?copy the exact preparation assignment}"
: "${PREPARED_ENROLLED_VARS:?copy the exact preparation assignment}"
"${ROOT_SMOKE[@]}" --secure-preparation-receipt "$SECURE_PREPARATION_RECEIPT" \
  uki "$SIGNED_RECOVERY_UKI" secure-boot \
  --firmware-code "$PREPARED_SECURE_CODE" \
  --firmware-vars "$PREPARED_ENROLLED_VARS"
```

Run the launcher as root. It verifies the root-only base receipt plus exact
harness/guard hashes before candidate Bash starts, binds fixed packaged OVMF
or strict Secure Boot preparation outputs into a private per-run receipt, then
drops the smoke run to an unassigned UID with no capabilities in a fresh
network namespace. Inputs live below one fresh retained-work root, QEMU uses
TCG and its deny sandbox, and the root supervisor retires survivors and cleans
that root before writing a private `PASS` receipt. A PASS requires an exact
bounded harness outcome plus a strict result document whose private serial
snapshots are independently rehashed and re-parsed by the root supervisor. The
receipt keeps only control roles, outcomes, byte counts, and SHA-256 values;
raw serial text remains private validation material. Direct harness invocation
is not a release gate.

Expected results are, respectively: BIOS ISO readiness, ordinary UEFI ISO
readiness, ordinary UEFI UKI readiness, and both observed unsigned-image
rejection and signed-image readiness. The Secure Boot harness derives the
unsigned control by removing the signature from the exact signed snapshot,
reattaches that signature, and requires byte-for-byte reconstruction before
booting. Its stripped digest must also equal the builder-attested unsigned
validation UKI. Each VM receives an independent mutable copy of the same immutable
disposable-key variables template; firmware-mutated state is never reused
between the negative and positive controls. A readiness marker proves service
startup only. It does not prove any storage, network, repair, or rollback
scenario below.

`prepare-secure-boot.py` is the only supported preparation path for this gate.
Its root preflight opens the base receipt without following links, verifies its
own attested source identity, validates fixed package-managed tools and an
unaltered `edk2-ovmf`, then runs all firmware parsing, disposable key creation,
enrollment, signing, and verification as the unmapped validation UID in a
fresh network namespace. It requires separate short-lived PK, KEK, and db
certificates; nonempty PK/KEK/db/dbx; `SecureBootEnable=01`; and
`CustomMode=00`. It never writes host firmware or uses enrolled owner keys.

Success is reported only after all private keys are absent, the exact signed
UKI/sidecar/enrolled-vars/secure-code outputs are reclaimed as root-owned
non-writable files, and a root-only strict receipt binds them to the builder
receipt and unsigned validation UKI. Failure or interruption produces no final
receipt. The smoke launcher independently parses that receipt, rejects any
replacement output, and derives its own negative control. Do not substitute a
manual `sbsign`, `virt-fw-vars --inplace`, `efi-updatevar`, or `sbctl
enroll-keys` workflow for release evidence.

| Boot gate | Candidate digest | Firmware/tool version | Result | Bounded serial log |
| --- | --- | --- | --- | --- |
| Hybrid ISO, BIOS | — | — | NOT RUN | — |
| Hybrid ISO, ordinary UEFI | — | — | NOT RUN | — |
| Local UKI, ordinary UEFI | — | — | NOT RUN | — |
| Unsigned UKI rejection control | — | — | NOT RUN | — |
| Signed UKI, disposable-key Secure Boot | — | — | NOT RUN | — |

## Booted recovery scenarios

The repository currently has no committed generator or harness for bootable
LUKS/Btrfs, ext4/LVM, snapshot, interrupted-package, Wi-Fi, or bootloader target
disks. Therefore none of these rows can inherit `PASS` from the deterministic
fixtures or the readiness smoke tests. Until a disposable target is created,
its pre-test digest and layout are recorded, the exact candidate is booted
against a nonpersistent copy, and the expected result below is observed, mark
the row `NOT RUN`.

A live row is a publication blocker when that subsystem changed in the release
or the public release claims its live outcome. Otherwise it may remain
`NOT RUN` only when the versioned public release note preserves that exact
limitation; the mandatory deterministic fixtures and BIOS/UEFI/UKI gates do
not become optional.

Invoke the runtime inside the booted candidate with AI disabled:

```bash
/usr/bin/aurascan recovery --runtime --no-ai
```

Use QEMU snapshot mode or a fresh copy of every target disk. Never attach a host
system disk, host ESP, enrolled owner keys, real saved Wi-Fi profile, or
non-test credentials.

| Scenario | Expected observable outcome | Result |
| --- | --- | --- |
| Offline boot | With no virtual NIC, deterministic diagnosis remains usable, network-required actions default to decline, and no provider request occurs. | NOT RUN |
| Controlled Ethernet/DHCP | A disposable virtual NIC is identified as Ethernet and obtains the test network state without importing host network profiles. This does not count as Wi-Fi coverage. | NOT RUN |
| Saved/manual Wi-Fi | On a disposable Wi-Fi test rig, only a validated test profile or hidden secret-agent input is used; the test secret is absent from argv, serial output, and saved release evidence. | NOT RUN |
| LUKS2 plus Btrfs | The intended encrypted target is selected explicitly, unlocking requires interactive hidden input, discovery starts read-only, and no repair runs before a confirmed writable transition. | NOT RUN |
| ext4 plus LVM2 | Only the intended logical volume activates, discovery and initial mount are read-only, and unrelated volumes remain unchanged. | NOT RUN |
| Interrupted package transaction | A deliberately interrupted disposable target produces only the bounded package/repository actions justified by its facts; signature/server preconditions fail closed. | NOT RUN |
| Snapshot restore | The exact typed confirmation is required, a new pre-recovery snapshot is proven before rollback, and the post-action state is revalidated. | NOT RUN |
| Initramfs failure rollback | A deliberately failing test generator leaves the original initramfs set byte-for-byte restored and removes partial outputs. | NOT RUN |
| Unknown or ambiguous bootloader | No reinstall action is offered and the target ESP, loader files, and firmware variables remain unchanged. | NOT RUN |
| Positively detected bootloader failure | With exact typed confirmation, only the detected loader recipe runs; forced command or post-validation failure restores backed-up loader files and does not modify firmware variables. | NOT RUN |

## Claim boundary

A recovery-bearing release may name only the gates recorded `PASS` for its
exact candidate. Use wording such as “the BIOS readiness marker was observed”
or “the deterministic LUKS refusal fixtures passed.” Do not broaden that into
“recovery was fully tested,” “all storage layouts work,” “the image contains no
secrets,” or “Secure Boot is supported” unless every corresponding live control
was actually run and recorded. `FAIL`, `NOT RUN`, missing evidence, a changed
candidate, or an unbounded/private log must remain visible and cannot be
converted into a passing release claim.
