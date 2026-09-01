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
validate_trusted_executable "$script_dir/qemu-uki-smoke.sh" \
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
      AURASCAN_OVMF_SECURE_CODE|AURASCAN_OVMF_ENROLLED_VARS_TEMPLATE|\
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
    AURASCAN_OVMF_SECURE_CODE="${AURASCAN_OVMF_SECURE_CODE-}" \
    AURASCAN_OVMF_ENROLLED_VARS_TEMPLATE="${AURASCAN_OVMF_ENROLLED_VARS_TEMPLATE-}" \
    AURASCAN_AI_ENABLED=0 AURASCAN_INSTRUCTION_AI_ENABLED=0 \
    AURASCAN_INCIDENT_AI_ENABLED=0 AURASCAN_RECOVERY_AI_ENABLED=0 \
    /usr/bin/bash --noprofile --norc -- "$0" "$@"
fi
builtin unset -f smoke_environment_is_minimal

set -euo pipefail
umask 077

usage() {
  printf 'Usage: %s UKI {uefi|secure-boot}\n' "$0" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
source_uki="$1"
mode="$2"
[[ "$mode" == "uefi" || "$mode" == "secure-boot" ]] || usage

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
  /usr/bin/setsid /usr/bin/timeout /usr/bin/env /usr/bin/sbverify \
  /usr/bin/sbattach /usr/bin/cp /usr/bin/chmod /usr/bin/grep /usr/bin/install \
  /usr/bin/kill /usr/bin/mktemp /usr/bin/readlink /usr/bin/rm /usr/bin/sleep \
  /usr/bin/stat; do
  validate_trusted_executable "$tool" || {
    printf 'Required trusted UKI smoke-test tool is unavailable\n' >&2
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
    --harness-role qemu_uki_harness \
    --harness "$script_dir/qemu-uki-smoke.sh" \
    --tool-guard "$tool_guard" --guard "$guard" \
    --kind uki --mode "$mode" --input "$source_uki"
}

verify_attested_context || {
  printf 'Recovery UKI smoke run lacks a valid private build attestation\n' >&2
  exit 1
}

timeout_seconds="${AURASCAN_QEMU_TIMEOUT_SECONDS:-300}"
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] && (( timeout_seconds >= 30 && timeout_seconds <= 900 )) || {
  printf 'AURASCAN_QEMU_TIMEOUT_SECONDS must be between 30 and 900\n' >&2
  exit 2
}

work="$(/usr/bin/mktemp -d --tmpdir="$TMPDIR" aurascan-uki-smoke.XXXXXXXX)"
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

uki="$work/signed-input.efi"
uki_digest="$(invoke_smoke_guard snapshot-release \
  --kind uki --source "$source_uki" --destination "$uki")" || exit 1
[[ "$uki_digest" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'Recovery UKI snapshot digest is invalid\n' >&2
  exit 1
}
attested_uki_digest="$(invoke_smoke_guard attested-digest \
  --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
  --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
  --mapping run_inputs --role selected_input)"
[[ "$uki_digest" == "$attested_uki_digest" ]] || {
  printf 'Recovery UKI snapshot differs from the root preflight attestation\n' >&2
  exit 1
}

run_signature_inventory() {
  local image="$1" image_digest="$2" label="$3" expected="$4"
  local output status=0 output_size
  output="$work/$label.sbverify"
  [[ ! -e "$output" && ! -L "$output" ]] || {
    printf 'Private UKI signature output path already exists\n' >&2
    return 1
  }
  invoke_smoke_guard verify-snapshot --kind uki \
    --path "$image" --sha256 "$image_digest" || return 1
  if (
    ulimit -f 64
    run_smoke_minimal /usr/bin/timeout --signal=TERM --kill-after=2s 15s \
      /usr/bin/sbverify --list "$image"
  ) > "$output" 2>&1; then
    status=0
  else
    status=$?
  fi
  output_size="$(/usr/bin/stat -c '%s' -- "$output")"
  (( status == 0 && output_size < 64 * 1024 )) || {
    printf 'UKI signature inventory failed or reached its output/runtime bound\n' >&2
    return 1
  }
  invoke_smoke_guard check-signature \
    --inventory "$output" --expect "$expected" || return 1
  invoke_smoke_guard verify-snapshot --kind uki \
    --path "$image" --sha256 "$image_digest" || return 1
}

run_sbattach() {
  local label="$1" output status=0 output_size
  shift
  output="$work/$label.sbattach"
  [[ ! -e "$output" && ! -L "$output" ]] || {
    printf 'Private UKI signature-operation output path already exists\n' >&2
    return 1
  }
  if (
    ulimit -f 64
    run_smoke_minimal /usr/bin/timeout --signal=TERM --kill-after=2s 15s \
      /usr/bin/sbattach "$@"
  ) > "$output" 2>&1; then
    status=0
  else
    status=$?
  fi
  output_size="$(/usr/bin/stat -c '%s' -- "$output")"
  (( status == 0 && output_size < 64 * 1024 )) || {
    printf 'UKI signature-table operation failed or reached its output/runtime bound\n' >&2
    return 1
  }
}

build_qemu() {
  local image="$1" image_digest="$2" code="$3" vars_template="$4" secure="$5" run_name="$6"
  local run_dir="$work/$run_name"
  /usr/bin/install -d -m 0700 -- "$run_dir/esp/EFI/BOOT" || return 1
  /usr/bin/cp -- "$image" "$run_dir/esp/EFI/BOOT/BOOTX64.EFI" || return 1
  /usr/bin/chmod 0400 -- "$run_dir/esp/EFI/BOOT/BOOTX64.EFI" || return 1
  /usr/bin/cp -- "$vars_template" "$run_dir/vars.fd" || return 1
  /usr/bin/chmod 0600 -- "$run_dir/vars.fd" || return 1
  invoke_smoke_guard verify-snapshot --kind uki \
    --path "$run_dir/esp/EFI/BOOT/BOOTX64.EFI" --sha256 "$image_digest" || return 1
  qemu=(
    /usr/bin/qemu-system-x86_64
    -machine q35,smm=on
    -m 3072
    -smp 2
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code"
    -drive "if=pflash,format=raw,unit=1,file=$run_dir/vars.fd"
    -drive "if=virtio,format=raw,readonly=on,file=fat:ro:$run_dir/esp"
    -boot order=c
    -display none
    -serial stdio
    -monitor none
    -net none
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
    -no-reboot
    -accel tcg
    -cpu max
    -global "driver=cfi.pflash01,property=secure,value=$secure"
  )
}

run_ready() {
  local image="$1" image_digest="$2" code="$3" code_digest="$4"
  local vars_template="$5" vars_digest="$6" secure="$7" run_name="$8"
  local log="$work/$run_name/serial.log" runner_pid log_size
  invoke_smoke_guard verify-snapshot --kind uki \
    --path "$image" --sha256 "$image_digest" || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$code" --sha256 "$code_digest" || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$vars_template" --sha256 "$vars_digest" || return 1
  build_qemu "$image" "$image_digest" "$code" "$vars_template" "$secure" "$run_name" \
    || return 1
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
    /usr/bin/grep -Eq '^AURASCAN_RECOVERY_READY$|^\[ *[0-9]+\.[0-9]{6}\] aurascan-recovery-marker\[[1-9][0-9]*\]: AURASCAN_RECOVERY_READY$' "$log" && break
    /usr/bin/sleep 1
  done
  /usr/bin/kill -TERM -- "-$runner_pid" 2>/dev/null || true
  wait "$runner_pid" 2>/dev/null || true
  active_runner_pid=""
  invoke_smoke_guard verify-snapshot --kind uki \
    --path "$work/$run_name/esp/EFI/BOOT/BOOTX64.EFI" --sha256 "$image_digest" \
    || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$code" --sha256 "$code_digest" || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$vars_template" --sha256 "$vars_digest" || return 1
  invoke_smoke_guard evaluate-log --log "$log" --expect ready || return 1
}

run_rejection() {
  local image="$1" image_digest="$2" code="$3" code_digest="$4"
  local vars_template="$5" vars_digest="$6" run_name="$7" log runner_pid status=0
  log="$work/$run_name/serial.log"
  invoke_smoke_guard verify-snapshot --kind uki \
    --path "$image" --sha256 "$image_digest" || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$code" --sha256 "$code_digest" || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$vars_template" --sha256 "$vars_digest" || return 1
  build_qemu "$image" "$image_digest" "$code" "$vars_template" on "$run_name" \
    || return 1
  # Do not stop when rejection-like prose first appears. The unsigned control
  # receives the complete bounded run; only the final immutable log is judged.
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
  if wait "$runner_pid"; then
    status=0
  else
    status=$?
  fi
  active_runner_pid=""
  # The negative control must remain under observation for the full interval;
  # an early firmware/QEMU exit is not proof of Secure Boot rejection.
  (( status == 124 )) || {
    printf 'Unsigned Secure Boot control ended before the full bounded interval\n' >&2
    return 1
  }
  invoke_smoke_guard verify-snapshot --kind uki \
    --path "$work/$run_name/esp/EFI/BOOT/BOOTX64.EFI" --sha256 "$image_digest" \
    || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$code" --sha256 "$code_digest" || return 1
  invoke_smoke_guard verify-snapshot --kind firmware \
    --path "$vars_template" --sha256 "$vars_digest" || return 1
  invoke_smoke_guard evaluate-log \
    --log "$log" --expect firmware-rejection || return 1
}

if [[ "$mode" == "uefi" ]]; then
  : "${AURASCAN_OVMF_CODE:?Set AURASCAN_OVMF_CODE to an ordinary OVMF code image}"
  : "${AURASCAN_OVMF_VARS_TEMPLATE:?Set AURASCAN_OVMF_VARS_TEMPLATE to matching ordinary OVMF variables}"
  code="$work/ovmf-code.fd"
  vars_template="$work/ovmf-vars-template.fd"
  code_digest="$(invoke_smoke_guard snapshot-opaque \
    --source "$AURASCAN_OVMF_CODE" --destination "$code")" || exit 1
  vars_digest="$(invoke_smoke_guard snapshot-opaque \
    --source "$AURASCAN_OVMF_VARS_TEMPLATE" --destination "$vars_template")" || exit 1
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
  run_ready "$uki" "$uki_digest" "$code" "$code_digest" \
    "$vars_template" "$vars_digest" off ordinary || {
    printf 'Ordinary UEFI UKI smoke test failed: bounded serial readiness marker was not observed\n' >&2
    exit 1
  }
  invoke_smoke_guard verify-snapshot --kind uki --path "$uki" --sha256 "$uki_digest"
  verify_attested_context || {
    printf 'Recovery UKI attested inputs changed during the smoke run\n' >&2
    exit 1
  }
  invoke_smoke_guard write-result \
    --destination "$TMPDIR/recovery-smoke-result.json" \
    --kind uki --mode uefi --ready-log "$work/ordinary/serial.log" || exit 1
  printf 'Ordinary UEFI UKI smoke test passed: recovery service reached the boot-readiness marker\n'
  exit 0
fi

run_signature_inventory "$uki" "$uki_digest" signed-input signed || {
  printf 'Secure Boot requires a signature-bearing UKI\n' >&2
  exit 1
}
unsigned="$work/unsigned-control.efi"
invoke_smoke_guard verify-snapshot --kind uki --path "$uki" --sha256 "$uki_digest"
/usr/bin/cp -- "$uki" "$unsigned"
/usr/bin/chmod 0600 -- "$unsigned"
invoke_smoke_guard verify-snapshot --kind uki \
  --path "$unsigned" --sha256 "$uki_digest"
[[ ! -e "$work/detached.raw" && ! -L "$work/detached.raw" ]] || {
  printf 'Private detached-signature path already exists\n' >&2
  exit 1
}
run_sbattach detach --detach "$work/detached.raw" --remove "$unsigned"
/usr/bin/chmod 0400 -- "$unsigned"
unsigned_digest="$(invoke_smoke_guard snapshot-digest --kind uki --path "$unsigned")"
base_unsigned_digest="$(invoke_smoke_guard attested-digest \
  --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
  --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
  --mapping files --role validation_uki)"
[[ "$unsigned_digest" == "$base_unsigned_digest" ]] || {
  printf 'Signature-stripped UKI differs from the attested exact-candidate validation UKI\n' >&2
  exit 1
}
detached="$work/detached-signature.p7"
detached_digest="$(invoke_smoke_guard snapshot-opaque \
  --source "$work/detached.raw" --destination "$detached")" || exit 1
[[ "$detached_digest" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'Detached UKI signature snapshot digest is invalid\n' >&2
  exit 1
}
reattached="$work/reattached-control.efi"
/usr/bin/cp -- "$unsigned" "$reattached"
/usr/bin/chmod 0600 -- "$reattached"
invoke_smoke_guard verify-snapshot --kind uki \
  --path "$reattached" --sha256 "$unsigned_digest"
invoke_smoke_guard verify-snapshot --kind firmware \
  --path "$detached" --sha256 "$detached_digest"
run_sbattach attach --attach "$detached" "$reattached"
/usr/bin/chmod 0400 -- "$reattached"
invoke_smoke_guard verify-payload-binding \
  --signed "$uki" --unsigned "$unsigned" --reattached "$reattached"
invoke_smoke_guard verify-snapshot --kind uki \
  --path "$reattached" --sha256 "$uki_digest"
invoke_smoke_guard verify-snapshot --kind firmware \
  --path "$detached" --sha256 "$detached_digest"
run_signature_inventory "$unsigned" "$unsigned_digest" unsigned-control unsigned
run_signature_inventory "$reattached" "$uki_digest" reattached-control signed

: "${AURASCAN_OVMF_SECURE_CODE:?Set AURASCAN_OVMF_SECURE_CODE to a Secure Boot OVMF code image}"
: "${AURASCAN_OVMF_ENROLLED_VARS_TEMPLATE:?Set AURASCAN_OVMF_ENROLLED_VARS_TEMPLATE to vars containing only disposable enrolled test keys}"
code="$work/secure-code.fd"
vars_template="$work/secure-vars-template.fd"
code_digest="$(invoke_smoke_guard snapshot-opaque \
  --source "$AURASCAN_OVMF_SECURE_CODE" --destination "$code")" || exit 1
vars_digest="$(invoke_smoke_guard snapshot-opaque \
  --source "$AURASCAN_OVMF_ENROLLED_VARS_TEMPLATE" --destination "$vars_template")" || exit 1
[[ "$code_digest" == "$(invoke_smoke_guard attested-digest \
    --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
    --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
    --mapping firmware --role ovmf_secure_code)" \
   && "$vars_digest" == "$(invoke_smoke_guard attested-digest \
    --attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH" \
    --fd "$AURASCAN_RECOVERY_ATTESTATION_FD" \
    --mapping firmware --role ovmf_enrolled_vars_template)" ]] || {
  printf 'Secure Boot OVMF snapshot differs from the root preflight attestation\n' >&2
  exit 1
}

run_rejection "$unsigned" "$unsigned_digest" "$code" "$code_digest" \
  "$vars_template" "$vars_digest" unsigned || {
  printf 'Secure Boot control failed: firmware-attributable unsigned UKI rejection was not proven\n' >&2
  exit 1
}
run_ready "$uki" "$uki_digest" "$code" "$code_digest" \
  "$vars_template" "$vars_digest" on signed || {
  printf 'Secure Boot signed-image test failed: bounded serial readiness marker was not observed\n' >&2
  exit 1
}
invoke_smoke_guard verify-snapshot --kind uki --path "$uki" --sha256 "$uki_digest"
verify_attested_context || {
  printf 'Secure Boot attested inputs changed during the smoke run\n' >&2
  exit 1
}
invoke_smoke_guard write-result \
  --destination "$TMPDIR/recovery-smoke-result.json" \
  --kind uki --mode secure-boot \
  --ready-log "$work/signed/serial.log" \
  --rejection-log "$work/unsigned/serial.log" || exit 1
printf 'Secure Boot UKI smoke test passed: payload-bound unsigned rejection and signed recovery readiness were both proven\n'
