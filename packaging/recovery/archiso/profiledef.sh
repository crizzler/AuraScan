#!/usr/bin/env bash

iso_name="aurascan-recovery"
iso_label="AURASCAN_RECOVER"
iso_publisher="AuraScan <https://github.com/crizzler/AuraScan>"
iso_application="AuraScan AI-Assisted Recovery"
iso_version="0.6.0"
install_dir="aurascan"
buildmodes=('iso')
bootmodes=('bios.syslinux' 'uefi.systemd-boot')
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '15')
if ! declare -p file_permissions >/dev/null 2>&1; then
  declare -A file_permissions=()
fi
file_permissions["/etc/shadow"]="0:0:400"
file_permissions["/root"]="0:0:700"
