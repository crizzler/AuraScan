#!/usr/bin/env bash

iso_name="aurascan-recovery"
iso_label="AURASCAN_RECOVER"
iso_publisher="AuraScan <https://github.com/crizzler/AuraScan>"
iso_application="AuraScan AI-Assisted Recovery"
: "${AURASCAN_RECOVERY_VERSION:?AURASCAN_RECOVERY_VERSION must match the packaged AuraScan release}"
iso_version="$AURASCAN_RECOVERY_VERSION"
install_dir="aurascan"
buildmodes=('iso')
bootmodes=('bios.syslinux' 'uefi.systemd-boot')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M')
if ! declare -p file_permissions >/dev/null 2>&1; then
  declare -A file_permissions=()
fi
file_permissions["/etc/shadow"]="0:0:400"
file_permissions["/root"]="0:0:700"
