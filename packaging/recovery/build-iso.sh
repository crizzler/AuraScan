#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
profile_source="$repo_root/packaging/recovery/archiso"
archiso_base="${AURASCAN_ARCHISO_BASE:-/usr/share/archiso/configs/releng}"
output="${1:-$repo_root/dist/recovery}"
work="${AURASCAN_ARCHISO_WORK:-$repo_root/.build/recovery-archiso}"
profile="$work/profile"
package_repo="$work/package-repo"
package_build="$work/arch-package"
package_cache="${AURASCAN_ARCHISO_CACHE:-$HOME/.cache/aurascan/recovery-archiso}"

command -v mkarchiso >/dev/null || { printf 'mkarchiso is required\n' >&2; exit 1; }
command -v repo-add >/dev/null || { printf 'repo-add is required\n' >&2; exit 1; }
command -v git >/dev/null || { printf 'git is required\n' >&2; exit 1; }
test -f "$archiso_base/profiledef.sh" || { printf 'Archiso releng profile is unavailable at %s\n' "$archiso_base" >&2; exit 1; }
test -z "$(git -C "$repo_root" status --porcelain)" || { printf 'Recovery ISO builds require a clean committed worktree\n' >&2; exit 1; }
install -d -m 0755 "$output" "$work" "$package_cache"
rm -rf "$profile" "$package_repo" "$package_build"
install -d -m 0755 "$package_repo" "$package_build"
install -d -m 0755 "$profile"
cp -a "$archiso_base"/. "$profile"/
cp -a "$profile_source"/airootfs/. "$profile"/airootfs/
install -d -m 0755 "$profile/airootfs/etc/systemd/system/multi-user.target.wants"
ln -sfn /usr/lib/systemd/system/aurascan-recovery.service \
  "$profile/airootfs/etc/systemd/system/multi-user.target.wants/aurascan-recovery.service"
ln -sfn /dev/null "$profile/airootfs/etc/systemd/system/getty@tty1.service"
cat "$profile_source/profiledef.sh" >> "$profile/profiledef.sh"
cp "$profile_source/pacman.conf" "$profile/pacman.conf"
sed -i "/^\[options\]$/a CacheDir = $package_cache" "$profile/pacman.conf"
cat "$profile_source/packages.x86_64" >> "$profile/packages.x86_64"
# The releng base adds the standard kernel and its kernel-specific Broadcom
# module. AuraScan ships linux-lts as its single recovery kernel and retains
# the firmware plus in-kernel Broadcom drivers.
sed -i -e '/^linux$/d' -e '/^broadcom-wl$/d' "$profile/packages.x86_64"
rm -f "$profile/airootfs/etc/mkinitcpio.d/linux.preset"
find "$profile/syslinux" "$profile/efiboot" "$profile/grub" -type f -exec sed -E -i \
  -e 's#vmlinuz-linux([[:space:]]|$)#vmlinuz-linux-lts\1#g' \
  -e 's#initramfs-linux\.img([[:space:]]|$)#initramfs-linux-lts.img\1#g' {} +
if grep -R -E 'vmlinuz-linux([[:space:]]|$)|initramfs-linux\.img([[:space:]]|$)' \
  "$profile/syslinux" "$profile/efiboot" "$profile/grub"; then
  printf 'Recovery bootloader configuration still references the removed standard kernel\n' >&2
  exit 1
fi
sort -u -o "$profile/packages.x86_64" "$profile/packages.x86_64"

pkgver="$(sed -n 's/^pkgver=//p' "$repo_root/packaging/arch/PKGBUILD")"
[[ "$pkgver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'Could not validate AuraScan package version\n' >&2; exit 1; }
iso_version="$(sed -n 's/^iso_version="\([^"]*\)"/\1/p' "$profile_source/profiledef.sh")"
test "$pkgver" = "$iso_version" || { printf 'Arch package version %s does not match recovery ISO version %s\n' "$pkgver" "$iso_version" >&2; exit 1; }
cp "$repo_root/packaging/arch/PKGBUILD" "$repo_root/packaging/arch/aurascan.install" "$package_build/"
git -C "$repo_root" archive --format=tar --prefix="AuraScan-$pkgver/" HEAD | gzip -n > "$package_build/AuraScan-$pkgver.tar.gz"
archive_sha="$(sha256sum "$package_build/AuraScan-$pkgver.tar.gz" | awk '{print $1}')"
sed -i \
  -e "s|^source=.*|source=('AuraScan-$pkgver.tar.gz')|" \
  -e "s|^sha256sums=.*|sha256sums=('$archive_sha')|" \
  "$package_build/PKGBUILD"
(
  cd "$package_build"
  /usr/bin/makepkg --clean --syncdeps --noconfirm
)
cp "$package_build"/aurascan-*.pkg.tar.* "$package_repo/"
repo-add "$package_repo/aurascan-recovery.db.tar.zst" "$package_repo"/aurascan-*.pkg.tar.*
package_repo_uri="$(python -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve().as_uri())' "$package_repo")"
cat >> "$profile/pacman.conf" <<EOF

[aurascan-recovery]
SigLevel = Optional TrustAll
Server = $package_repo_uri
EOF

mkarchiso_bin="$(command -v mkarchiso)"
mkarchiso_runner="$mkarchiso_bin"
# Archiso 88 accidentally writes the absolute modules.alias path before the
# compressed HDT payload. Use a private corrected copy until upstream releases
# a version without the malformed, privacy-leaking `-print` expression.
if grep -Eq "modules\\.alias.*-print -exec gzip" "$mkarchiso_bin"; then
  mkarchiso_runner="$work/mkarchiso-aurascan"
  install -m 0755 "$mkarchiso_bin" "$mkarchiso_runner"
  sed -i '/modules\.alias/s/ -print -exec gzip/ -exec gzip/' "$mkarchiso_runner"
  if grep -Eq "modules\\.alias.*-print -exec gzip" "$mkarchiso_runner"; then
    printf 'Could not apply the Archiso modules.alias privacy correction\n' >&2
    exit 1
  fi
fi

mkarchiso_command=("$mkarchiso_runner" -v -w "$work" -o "$output" "$profile")
if (( EUID == 0 )); then
  "${mkarchiso_command[@]}"
else
  root_helper="${AURASCAN_ARCHISO_ROOT_HELPER:-sudo}"
  case "$root_helper" in
    sudo|doas|pkexec)
      command -v "$root_helper" >/dev/null || {
        printf 'Requested Archiso privilege helper is unavailable: %s\n' "$root_helper" >&2
        exit 1
      }
      "$root_helper" "${mkarchiso_command[@]}"
      ;;
    run0)
      command -v run0 >/dev/null || { printf 'run0 is unavailable\n' >&2; exit 1; }
      run0 --pipe "${mkarchiso_command[@]}"
      ;;
    *)
      printf 'Unsupported AURASCAN_ARCHISO_ROOT_HELPER: %s\n' "$root_helper" >&2
      exit 1
      ;;
  esac
fi

iso="$(find "$output" -maxdepth 1 -type f -name '*.iso' -print -quit)"
test -n "$iso"
modalias="$work/iso/boot/syslinux/hdt/modalias.gz"
if [[ -f "$modalias" ]] && ! gzip -t "$modalias"; then
  printf 'Archiso produced a malformed SYSLINUX module-alias payload\n' >&2
  exit 1
fi
if grep -aFq "$repo_root" "$iso" || grep -aFq "$HOME" "$iso"; then
  printf 'Recovery ISO contains a developer-local build path\n' >&2
  exit 1
fi
iso_dir="$(dirname "$iso")"
iso_name="$(basename "$iso")"
(cd "$iso_dir" && sha256sum "$iso_name" | tee "$iso_name.sha256")
installed_packages="$work/iso/aurascan/pkglist.x86_64.txt"
test -f "$installed_packages" || { printf 'Archiso package manifest was not produced\n' >&2; exit 1; }
LC_ALL=C sort -u "$installed_packages" > "$iso.packages.txt"
printf 'Built hybrid BIOS/UEFI recovery image: %s\n' "$iso"
