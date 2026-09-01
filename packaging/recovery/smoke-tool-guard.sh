#!/usr/bin/bash
# Shared trusted-executable boundary for recovery smoke harnesses.

validate_trusted_component() {
  local component="$1" expected_type="$2" component_mode component_owner
  [[ ! -L "$component" ]] || return 1
  if [[ "$expected_type" == "directory" ]]; then
    [[ -d "$component" ]] || return 1
  else
    [[ -f "$component" && -x "$component" ]] || return 1
  fi
  component_mode="$(/usr/bin/stat -c '%a' -- "$component" 2>/dev/null)" || return 1
  component_owner="$(/usr/bin/stat -c '%u' -- "$component" 2>/dev/null)" || return 1
  [[ "$component_mode" =~ ^[0-7]+$ && "$component_owner" == "0" ]] || return 1
  (( (8#$component_mode & 8#022) == 0 ))
}

bootstrap_trusted_stat() {
  # Bash's type/link tests establish the fixed bootstrap shape before stat is
  # allowed to attest ownership and mode for itself and its parent chain.
  [[ -d / && ! -L / && -d /usr && ! -L /usr && \
     -d /usr/bin && ! -L /usr/bin && \
     -f /usr/bin/stat && -x /usr/bin/stat && ! -L /usr/bin/stat ]] || return 1
  validate_trusted_component / directory \
    && validate_trusted_component /usr directory \
    && validate_trusted_component /usr/bin directory \
    && validate_trusted_component /usr/bin/stat executable
}

validate_trusted_executable() {
  local tool="$1" remainder current="" part index
  local -a components
  [[ "$tool" == /* && "$tool" != */ && "$tool" != *","* \
     && ! "$tool" =~ [[:cntrl:]] ]] || return 1
  remainder="${tool#/}"
  IFS=/ read -r -a components <<< "$remainder"
  (( ${#components[@]} > 0 )) || return 1
  validate_trusted_component / directory || return 1
  for (( index = 0; index < ${#components[@]}; index++ )); do
    part="${components[index]}"
    [[ -n "$part" && "$part" != "." && "$part" != ".." ]] || return 1
    current="$current/$part"
    if (( index + 1 == ${#components[@]} )); then
      validate_trusted_component "$current" executable || return 1
    else
      validate_trusted_component "$current" directory || return 1
    fi
  done
}

if ! bootstrap_trusted_stat; then
  printf 'Trusted tool path bootstrap failed\n' >&2
  if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    exit 1
  fi
  return 1
fi

run_smoke_minimal() {
  local smoke_runtime="${TMPDIR-}" smoke_run_root smoke_builder attestation_fd
  (( $# > 0 )) || return 2
  validate_trusted_executable /usr/bin/env || return 1
  validate_trusted_executable "$1" || return 1
  # Recheck the launcher-shaped runtime and inherited private-attestation
  # descriptor before preserving TMPDIR.  The guard's verify-attestation
  # operation performs the content binding; no other caller environment is
  # forwarded to the selected tool.
  [[ "${AURASCAN_RECOVERY_SMOKE_CLEAN_ENV-}" == "1" \
     && "$smoke_runtime" =~ ^/var/lib/aurascan-recovery-builder/([A-Za-z0-9._-]+)/recovery-validation-run-[0-9a-f]{24}/runtime$ ]] \
    || return 1
  smoke_builder="${BASH_REMATCH[1]}"
  [[ "$smoke_builder" != "." && "$smoke_builder" != ".." ]] || return 1
  smoke_run_root="${smoke_runtime%/runtime}"
  attestation_fd="${AURASCAN_RECOVERY_ATTESTATION_FD-}"
  [[ "${AURASCAN_RECOVERY_ATTESTATION_PATH-}" \
       == "$smoke_run_root/inputs/recovery-validation-attestation.json" \
     && "$attestation_fd" =~ ^([3-9]|[1-9][0-9]+)$ ]] \
    || return 1
  builtin : <&"$attestation_fd" || return 1
  /usr/bin/env -i \
    PATH=/usr/bin:/bin HOME=/nonexistent USER=aurascan LOGNAME=aurascan \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
    TMPDIR="$smoke_runtime" \
    AURASCAN_AI_ENABLED=0 AURASCAN_INSTRUCTION_AI_ENABLED=0 \
    AURASCAN_INCIDENT_AI_ENABLED=0 AURASCAN_RECOVERY_AI_ENABLED=0 \
    "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  (( $# > 0 )) || {
    printf 'No trusted executable was selected\n' >&2
    exit 2
  }
  for selected_tool in "$@"; do
    validate_trusted_executable "$selected_tool" || {
      printf 'Executable failed the trusted path-component boundary\n' >&2
      exit 1
    }
  done
fi
