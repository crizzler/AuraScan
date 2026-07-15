# AuraScan Recovery Release Images

`build-iso.sh` creates the hybrid BIOS/UEFI USB image from the same packaged
AuraScan release used by the Arch package. It emits both a SHA-256 sidecar and
the sorted package manifest.

Release sequence:

1. Commit a clean release candidate with version `0.6.0` and the ISO manifest
   digest left empty. The builder packages that exact commit with `git archive`;
   it never downloads an older tag.
2. Run `packaging/recovery/build-iso.sh` on a clean Arch builder with `archiso`.
   Package creation stays unprivileged; only `mkarchiso` is elevated. The
   default helper is `sudo`. Set `AURASCAN_ARCHISO_ROOT_HELPER` to `doas`,
   `pkexec`, or `run0` when that is the builder's normal privilege boundary.
   Arch packages use an isolated, signature-checked cache under
   `~/.cache/aurascan/recovery-archiso` by default so Arch and downstream
   packages with identical filenames cannot be mixed. Override it with
   `AURASCAN_ARCHISO_CACHE` when the builder provides an equally isolated path.
3. Boot the ISO with `qemu-smoke.sh ISO bios` and `uefi`. Boot the locally
   built UKI with `qemu-uki-smoke.sh UKI uefi` and
   `qemu-uki-smoke.sh UKI secure-boot` using matching OVMF variables.
4. Complete the encrypted Btrfs and ext4/LVM recovery scenarios from the
   release checklist.
5. Place the tested ISO's SHA-256 digest in `aurascan-recovery-iso.json`, commit
   that host-package metadata, create the final tag, and upload the exact ISO.
   The ISO intentionally contains the release-candidate placeholder manifest;
   the final host/AUR package contains the pinned download digest, avoiding a
   self-referential artifact hash.

The build profile contains no API key, Wi-Fi profile, hostname, incident
evidence, or user home. The release must fail if the artifact credential scan
or any firmware boot check fails.
