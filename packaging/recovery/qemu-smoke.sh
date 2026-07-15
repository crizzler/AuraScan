#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s ISO {bios|uefi}\n' "$0" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
iso="$(realpath -- "$1")"
mode="$2"
[[ -f "$iso" ]] || { printf 'ISO not found: %s\n' "$iso" >&2; exit 1; }
command -v qemu-system-x86_64 >/dev/null || {
  printf 'qemu-system-x86_64 is required\n' >&2
  exit 1
}
command -v run_archiso >/dev/null || {
  printf 'run_archiso from archiso is required\n' >&2
  exit 1
}

if [[ -f "$iso.sha256" ]]; then
  (cd "$(dirname "$iso")" && sha256sum --check "$(basename "$iso").sha256")
else
  printf 'Refusing an unverified ISO; expected %s.sha256\n' "$iso" >&2
  exit 1
fi

case "$mode" in
  bios)
    exec run_archiso -i "$iso"
    ;;
  uefi)
    exec run_archiso -u -i "$iso"
    ;;
  *) usage ;;
esac
