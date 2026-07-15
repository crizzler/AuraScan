#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s UKI {uefi|secure-boot}\n' "$0" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
uki="$(realpath -- "$1")"
mode="$2"
[[ "$mode" == "uefi" || "$mode" == "secure-boot" ]] || usage
[[ -f "$uki" ]] || { printf 'UKI not found: %s\n' "$uki" >&2; exit 1; }
[[ -f "$uki.sha256" ]] || { printf 'Refusing an unverified UKI; expected %s.sha256\n' "$uki" >&2; exit 1; }
(cd "$(dirname "$uki")" && sha256sum --check "$(basename "$uki").sha256")
[[ "$(head -c 2 "$uki")" == "MZ" ]] || { printf 'Input is not a PE/COFF UKI\n' >&2; exit 1; }

command -v qemu-system-x86_64 >/dev/null || { printf 'qemu-system-x86_64 is required\n' >&2; exit 1; }
: "${AURASCAN_OVMF_CODE:?Set AURASCAN_OVMF_CODE to the OVMF code image}"
: "${AURASCAN_OVMF_VARS_TEMPLATE:?Set AURASCAN_OVMF_VARS_TEMPLATE to a matching vars template}"
[[ -f "$AURASCAN_OVMF_CODE" && -f "$AURASCAN_OVMF_VARS_TEMPLATE" ]] || {
  printf 'OVMF code or vars template was not found\n' >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/esp/EFI/BOOT"
cp -- "$uki" "$work/esp/EFI/BOOT/BOOTX64.EFI"
cp -- "$AURASCAN_OVMF_VARS_TEMPLATE" "$work/vars.fd"

printf 'Booting %s UKI smoke test. Confirm that AuraScan Recovery reaches target discovery.\n' "$mode"
qemu-system-x86_64 \
  -machine q35,smm=on \
  -m 4096 \
  -cpu host \
  -enable-kvm \
  -drive "if=pflash,format=raw,readonly=on,file=$AURASCAN_OVMF_CODE" \
  -drive "if=pflash,format=raw,file=$work/vars.fd" \
  -drive "format=raw,file=fat:rw:$work/esp" \
  -boot c \
  -no-reboot
