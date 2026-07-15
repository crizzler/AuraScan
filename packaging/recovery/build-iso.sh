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

command -v mkarchiso >/dev/null || { printf 'mkarchiso is required\n' >&2; exit 1; }
command -v repo-add >/dev/null || { printf 'repo-add is required\n' >&2; exit 1; }
command -v git >/dev/null || { printf 'git is required\n' >&2; exit 1; }
test -f "$archiso_base/profiledef.sh" || { printf 'Archiso releng profile is unavailable at %s\n' "$archiso_base" >&2; exit 1; }
test -z "$(git -C "$repo_root" status --porcelain)" || { printf 'Recovery ISO builds require a clean committed worktree\n' >&2; exit 1; }
install -d -m 0755 "$output" "$work"
rm -rf "$profile" "$package_repo" "$package_build"
install -d -m 0755 "$package_repo" "$package_build"
install -d -m 0755 "$profile"
cp -a "$archiso_base"/. "$profile"/
cp -a "$profile_source"/airootfs/. "$profile"/airootfs/
install -d -m 0755 "$profile/airootfs/etc/systemd/system/multi-user.target.wants"
ln -sfn /usr/lib/systemd/system/aurascan-recovery.service \
  "$profile/airootfs/etc/systemd/system/multi-user.target.wants/aurascan-recovery.service"
cat "$profile_source/profiledef.sh" >> "$profile/profiledef.sh"
cp "$profile_source/pacman.conf" "$profile/pacman.conf"
cat "$profile_source/packages.x86_64" >> "$profile/packages.x86_64"
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
cat >> "$profile/pacman.conf" <<EOF

[aurascan-recovery]
SigLevel = Optional TrustAll
Server = file://$package_repo
EOF

mkarchiso -v -w "$work" -o "$output" "$profile"

iso="$(find "$output" -maxdepth 1 -type f -name '*.iso' -print -quit)"
test -n "$iso"
sha256sum "$iso" | tee "$iso.sha256"
LC_ALL=C sort -u "$profile/packages.x86_64" > "$iso.packages.txt"
printf 'Built hybrid BIOS/UEFI recovery image: %s\n' "$iso"
