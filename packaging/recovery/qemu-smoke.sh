#!/usr/bin/bash

# This gate intentionally uses Bash builtins only.  The root launcher must
# establish the isolated identity, inherited receipt descriptor, and private
# run-root layout before this candidate harness may source even its adjacent
# guard code.
if [[ "$EUID" != "60998" || $# -ne 2 \
   || "${AURASCAN_RECOVERY_SMOKE_CLEAN_ENV-}" != "1" \
   || ! "${AURASCAN_RECOVERY_ATTESTATION_FD-}" =~ ^([3-9]|[1-9][0-9]+)$ \
   || ! "${TMPDIR-}" =~ ^/var/lib/aurascan-recovery-builder/[A-Za-z0-9._-]+/recovery-validation-run-[0-9a-f]{24}/runtime$ \
   || "${PWD-}" != "${TMPDIR-}" ]]; then
  builtin printf 'Recovery smoke harness requires the isolated root-launcher boundary\n' >&2
  builtin exit 1
fi
smoke_run_root="${TMPDIR%/runtime}"
if [[ "${AURASCAN_RECOVERY_ATTESTATION_PATH-}" \
      != "$smoke_run_root/inputs/recovery-validation-attestation.json" ]] \
   || ! builtin : <&"$AURASCAN_RECOVERY_ATTESTATION_FD"; then
  builtin printf 'Recovery smoke harness lacks its inherited private attestation\n' >&2
  builtin exit 1
fi
builtin unset smoke_run_root

smoke_script_path="${BASH_SOURCE[0]}"
case "$smoke_script_path" in
  */*) smoke_script_parent="${smoke_script_path%/*}" ;;
  *) smoke_script_parent=. ;;
esac
script_dir="$(builtin cd -- "$smoke_script_parent" && builtin pwd -P)" || {
  builtin printf 'Recovery smoke tool directory is unavailable\n' >&2
  exit 1
}
tool_guard="$script_dir/smoke-tool-guard.sh"
[[ -f "$tool_guard" && ! -L "$tool_guard" ]] || {
  builtin printf 'Recovery smoke tool guard is unavailable\n' >&2
  exit 1
}
builtin source "$tool_guard" || exit 1
validate_trusted_executable "$script_dir/qemu-smoke.sh" \
  && validate_trusted_executable "$tool_guard" || {
  builtin printf 'Recovery smoke harness is not rooted in a trusted release snapshot\n' >&2
  exit 1
}
validate_trusted_executable /usr/bin/env \
  && validate_trusted_executable /usr/bin/bash || {
  builtin printf 'Trusted smoke environment bootstrap is unavailable\n' >&2
  exit 1
}

smoke_environment_is_minimal() {
  local IFS=$' \t\n' exported_name
  [[ "${AURASCAN_RECOVERY_SMOKE_CLEAN_ENV-}" == "1" \
     && "${PATH-}" == "/usr/bin:/bin" && "${HOME-}" == "/nonexistent" \
     && "${USER-}" == "aurascan" && "${LOGNAME-}" == "aurascan" \
     && "${LANG-}" == "C.UTF-8" && "${LC_ALL-}" == "C.UTF-8" \
     && "${TZ-}" == "UTC" && "${AURASCAN_AI_ENABLED-}" == "0" \
     && "${AURASCAN_INSTRUCTION_AI_ENABLED-}" == "0" \
     && "${AURASCAN_INCIDENT_AI_ENABLED-}" == "0" \
     && "${AURASCAN_RECOVERY_AI_ENABLED-}" == "0" \
     && "${AURASCAN_RECOVERY_ATTESTATION_PATH-}" == /* \
     && "${AURASCAN_RECOVERY_ATTESTATION_FD-}" =~ ^[0-9]+$ \
     && "${TMPDIR-}" == /var/lib/aurascan-recovery-builder/*/runtime ]] || return 1
  for exported_name in $(builtin compgen -e); do
    case "$exported_name" in
      PATH|HOME|USER|LOGNAME|LANG|LC_ALL|TZ|PWD|SHLVL|_|\
      AURASCAN_RECOVERY_SMOKE_CLEAN_ENV|AURASCAN_QEMU_TIMEOUT_SECONDS|\
      AURASCAN_RECOVERY_ATTESTATION_PATH|AURASCAN_RECOVERY_ATTESTATION_FD|TMPDIR|\
      AURASCAN_OVMF_CODE|AURASCAN_OVMF_VARS_TEMPLATE|\
      AURASCAN_AI_ENABLED|AURASCAN_INSTRUCTION_AI_ENABLED|\
      AURASCAN_INCIDENT_AI_ENABLED|AURASCAN_RECOVERY_AI_ENABLED) ;;
      *) return 1 ;;
    esac
  done
}

if ! smoke_environment_is_minimal; then
  builtin exec /usr/bin/env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent USER=aurascan LOGNAME=aurascan \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    AURASCAN_RECOVERY_SMOKE_CLEAN_ENV=1 \
    AURASCAN_QEMU_TIMEOUT_SECONDS="${AURASCAN_QEMU_TIMEOUT_SECONDS:-300}" \
    AURASCAN_RECOVERY_ATTESTATION_PATH="${AURASCAN_RECOVERY_ATTESTATION_PATH-}" \
    AURASCAN_RECOVERY_ATTESTATION_FD="${AURASCAN_RECOVERY_ATTESTATION_FD-}" \
    TMPDIR="${TMPDIR-}" \
    AURASCAN_OVMF_CODE="${AURASCAN_OVMF_CODE-}" \
    AURASCAN_OVMF_VARS_TEMPLATE="${AURASCAN_OVMF_VARS_TEMPLATE-}" \
    AURASCAN_AI_ENABLED=0 AURASCAN_INSTRUCTION_AI_ENABLED=0 \
    AURASCAN_INCIDENT_AI_ENABLED=0 AURASCAN_RECOVERY_AI_ENABLED=0 \
    /usr/bin/bash --noprofile --norc -- "$0" "$@"
fi
builtin unset -f smoke_environment_is_minimal

set -euo pipefail
umask 077

usage() {
  printf 'Usage: %s ISO {bios|uefi}\n' "$0" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
source_iso="$1"
mode="$2"
[[ "$mode" == "bios" || "$mode" == "uefi" ]] || usage

guard="$script_dir/smoke_guard.py"
[[ -f "$guard" && ! -L "$guard" ]] || {
  printf 'Recovery smoke input guard is unavailable\n' >&2
  exit 1
}
validate_trusted_executable "$guard" || {
  printf 'Recovery smoke input guard is not rooted in a trusted release snapshot\n' >&2
  exit 1
}
validate_trusted_executable /usr/bin/readlink || {
  printf 'Trusted Python resolver is unavailable\n' >&2
  exit 1
}
python_bin="$(/usr/bin/readlink -e -- /usr/bin/python3)" || {
  printf 'Trusted system Python is unavailable\n' >&2
  exit 1
}
for tool in /usr/bin/bash "$python_bin" /usr/bin/qemu-system-x86_64 \
  /usr/bin/setsid /usr/bin/timeout /usr/bin/env /usr/bin/cp /usr/bin/chmod \
  /usr/bin/grep /usr/bin/install /usr/bin/kill /usr/bin/mktemp /usr/bin/readlink \
  /usr/bin/rm /usr/bin/sleep /usr/bin/stat; do
  validate_trusted_executable "$tool" || {
    printf 'Required trusted QEMU smoke-test tool is unavailable\n' >&2
    exit 1
  }
done

invoke_smoke_guard() {
  run_smoke_minimal "$python_bin" -I -S "$guard" "$@"
}

verify_attested_context() {
  invoke_smoke_guard verify-attestation \
    --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
    --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
    --harness-role qemu_iso_harness \
    --harness "$script_dir/qemu-smoke.sh" \
    --tool-guard "$tool_guard" --guard "$guard" \
    --kind iso --mode "$mode" --input "$source_iso"
}

verify_attested_context || {
  printf 'Recovery ISO smoke run lacks a valid private build attestation\n' >&2
  exit 1
}

timeout_seconds="${AURASCAN_QEMU_TIMEOUT_SECONDS:-300}"
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] && (( timeout_seconds >= 30 && timeout_seconds <= 900 )) || {
  printf 'AURASCAN_QEMU_TIMEOUT_SECONDS must be between 30 and 900\n' >&2
  exit 2
}

work="$(/usr/bin/mktemp -d --tmpdir="$TMPDIR" aurascan-iso-smoke.XXXXXXXX)"
active_runner_pid=""
cleanup() {
  local status=$?
  trap - HUP INT TERM EXIT
  if [[ "$active_runner_pid" =~ ^[0-9]+$ ]]; then
    /usr/bin/kill -TERM -- "-$active_runner_pid" 2>/dev/null || true
    wait "$active_runner_pid" 2>/dev/null || true
    active_runner_pid=""
  fi
  /usr/bin/rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/install -d -m 0700 -- "$work/home"

iso="$work/recovery.iso"
iso_digest="$(invoke_smoke_guard snapshot-release \
  --kind iso --source "$source_iso" --destination "$iso")" || exit 1
[[ "$iso_digest" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'Recovery ISO snapshot digest is invalid\n' >&2
  exit 1
}
attested_iso_digest="$(invoke_smoke_guard attested-digest \
  --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
  --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
  --mapping run_inputs --role selected_input)"
[[ "$iso_digest" == "$attested_iso_digest" ]] || {
  printf 'Recovery ISO snapshot differs from the private build attestation\n' >&2
  exit 1
}

code=""
code_digest=""
vars_template=""
vars_digest=""
if [[ "$mode" == "uefi" ]]; then
  : "${AURASCAN_OVMF_CODE:?Set AURASCAN_OVMF_CODE to an ordinary OVMF code image}"
  : "${AURASCAN_OVMF_VARS_TEMPLATE:?Set AURASCAN_OVMF_VARS_TEMPLATE to matching ordinary OVMF variables}"
  code="$work/ovmf-code.fd"
  vars_template="$work/ovmf-vars-template.fd"
  code_digest="$(invoke_smoke_guard snapshot-opaque \
    --source "$AURASCAN_OVMF_CODE" --destination "$code")" || exit 1
  vars_digest="$(invoke_smoke_guard snapshot-opaque \
    --source "$AURASCAN_OVMF_VARS_TEMPLATE" --destination "$vars_template")" || exit 1
fi
if [[ "$mode" == "uefi" ]]; then
  [[ "$code_digest" == "$(invoke_smoke_guard attested-digest \
      --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
      --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
      --mapping firmware --role ovmf_code)" \
     && "$vars_digest" == "$(invoke_smoke_guard attested-digest \
      --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
      --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
      --mapping firmware --role ovmf_vars_template)" ]] || {
    printf 'Recovery OVMF snapshot differs from the root preflight attestation\n' >&2
    exit 1
  }
fi

log="$work/serial.log"
qemu=(
  /usr/bin/qemu-system-x86_64
  -machine q35,smm=on
  -m 3072
  -smp 2
  -boot order=d
  -drive "file=$iso,media=cdrom,readonly=on"
  -display none
  -serial stdio
  -monitor none
  -net none
  -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
  -no-reboot
  -accel tcg
  -cpu max
)
if [[ "$mode" == "uefi" ]]; then
  /usr/bin/cp -- "$vars_template" "$work/vars.fd"
  /usr/bin/chmod 0600 -- "$work/vars.fd"
  qemu+=(
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code"
    -drive "if=pflash,format=raw,unit=1,file=$work/vars.fd"
    -global driver=cfi.pflash01,property=secure,value=off
  )
fi

invoke_smoke_guard verify-snapshot --kind iso --path "$iso" --sha256 "$iso_digest"
if [[ "$mode" == "uefi" ]]; then
  invoke_smoke_guard verify-snapshot --kind firmware --path "$code" --sha256 "$code_digest"
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$vars_template" --sha256 "$vars_digest"
fi

(
  ulimit -f "$((16 * 1024))"
  exec /usr/bin/setsid /usr/bin/timeout --signal=TERM --kill-after=10s \
    "${timeout_seconds}s" /usr/bin/env -i \
      PATH=/usr/bin:/bin HOME="$work/home" USER=aurascan LOGNAME=aurascan \
      LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
      AURASCAN_AI_ENABLED=0 AURASCAN_INSTRUCTION_AI_ENABLED=0 \
      AURASCAN_INCIDENT_AI_ENABLED=0 AURASCAN_RECOVERY_AI_ENABLED=0 \
      "${qemu[@]}"
) > "$log" 2>&1 &
runner_pid=$!
active_runner_pid="$runner_pid"
while /usr/bin/kill -0 "$runner_pid" 2>/dev/null; do
  log_size="$(/usr/bin/stat -c '%s' -- "$log")"
  (( log_size < 16 * 1024 * 1024 )) || break
  /usr/bin/grep -Eq $'^(\\[ *[0-9]+\\.[0-9]{6}\\] )?aurascan-recovery-marker\\[[1-9][0-9]*\\]: AURASCAN_RECOVERY_READY\r?$' "$log" && break
  /usr/bin/sleep 1
done
/usr/bin/kill -TERM -- "-$runner_pid" 2>/dev/null || true
wait "$runner_pid" 2>/dev/null || true
active_runner_pid=""

invoke_smoke_guard verify-snapshot --kind iso --path "$iso" --sha256 "$iso_digest"
if [[ "$mode" == "uefi" ]]; then
  invoke_smoke_guard verify-snapshot --kind firmware --path "$code" --sha256 "$code_digest"
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$vars_template" --sha256 "$vars_digest"
fi
invoke_smoke_guard evaluate-log --log "$log" --expect ready || {
  printf 'Recovery ISO smoke test failed: bounded serial readiness marker was not observed\n' >&2
  exit 1
}
verify_attested_context || {
  printf 'Recovery ISO attested inputs changed during the smoke run\n' >&2
  exit 1
}
invoke_smoke_guard write-result \
  --destination "$TMPDIR/recovery-smoke-result.json" \
  --kind iso --mode "$mode" --ready-log "$log" || exit 1
printf 'Recovery ISO %s smoke test passed: recovery service reached the boot-readiness marker\n' "$mode"
