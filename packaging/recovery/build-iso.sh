#!/usr/bin/bash
set -euo pipefail
umask 022

readonly expected_release_version="0.10.3"
readonly expected_release_date="2026-09-01"
readonly release_asset_limit=$((2 * 1024 * 1024 * 1024))
readonly isolated_build_uid=60999
readonly isolated_build_gid=60999
readonly build_base=/var/lib/aurascan-recovery-builder
script_dir="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)" || {
  printf 'Recovery builder directory could not be resolved\n' >&2
  exit 1
}
readonly script_dir
repo_root="$(cd -- "$script_dir/../.." && pwd -P)" || {
  printf 'AuraScan release checkout could not be resolved\n' >&2
  exit 1
}
readonly repo_root

if (( EUID != 0 )); then
  printf '%s\n' \
    'Recovery ISO construction must run entirely as root from a root-owned disposable checkout.' >&2
  exit 1
fi

[[ "${PATH:-}" == "/usr/bin:/bin" && "${HOME:-}" == "/root" && \
   "${USER:-}" == "root" && "${LOGNAME:-}" == "root" && \
   "${LANG:-}" == "C.UTF-8" && "${LC_ALL:-}" == "C.UTF-8" && \
   "${TZ:-}" == "UTC" ]] || {
  printf '%s\n' \
    'Recovery ISO construction requires the documented minimal root environment.' >&2
  exit 1
}
while IFS= read -r inherited_name; do
  case "$inherited_name" in
    HOME|LANG|LC_ALL|LOGNAME|PATH|PWD|SHLVL|TZ|USER|_) ;;
    *)
      printf 'Recovery ISO construction rejects inherited environment variable: %s\n' \
        "$inherited_name" >&2
      exit 1
      ;;
  esac
done < <(compgen -e)

resolve_trusted_tool() {
  local requested="$1" resolved component current owner permissions file_type
  resolved="$(/usr/bin/readlink -e -- "$requested")" || {
    printf 'Required system tool is unavailable: %s\n' "$requested" >&2
    return 1
  }
  case "$resolved" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/systemd/*) ;;
    *)
      printf 'System tool resolved outside a trusted system directory: %s\n' "$requested" >&2
      return 1
      ;;
  esac
  current=""
  IFS='/' read -r -a components <<< "${resolved#/}"
  for component in "${components[@]}"; do
    current="$current/$component"
    [[ ! -L "$current" ]] || {
      printf 'System tool has a symlinked resolved component: %s\n' "$requested" >&2
      return 1
    }
    owner="$(/usr/bin/stat -c '%u' -- "$current")"
    permissions="$(/usr/bin/stat -c '%a' -- "$current")"
    [[ "$owner" == "0" ]] || {
      printf 'System tool is not rooted in root-owned paths: %s\n' "$requested" >&2
      return 1
    }
    (( (8#$permissions & 8#022) == 0 )) || {
      printf 'System tool has a group/world-writable path component: %s\n' "$requested" >&2
      return 1
    }
  done
  file_type="$(/usr/bin/stat -c '%F' -- "$resolved")"
  [[ "$file_type" == "regular file" && -x "$resolved" ]] || {
    printf 'System tool is not an executable regular file: %s\n' "$requested" >&2
    return 1
  }
  printf '%s\n' "$resolved"
}

assert_root_safe_components() {
  local requested="$1" label="$2" resolved component current owner permissions
  resolved="$(/usr/bin/readlink -e -- "$requested")" || {
    printf '%s is unavailable: %s\n' "$label" "$requested" >&2
    return 1
  }
  [[ "$resolved" == "$requested" ]] || {
    printf '%s contains a symlinked or non-canonical component: %s\n' "$label" "$requested" >&2
    return 1
  }
  current=""
  IFS='/' read -r -a components <<< "${resolved#/}"
  for component in "${components[@]}"; do
    current="$current/$component"
    [[ ! -L "$current" ]] || {
      printf '%s has a symlinked path component: %s\n' "$label" "$current" >&2
      return 1
    }
    owner="$(/usr/bin/stat -c '%u' -- "$current")"
    permissions="$(/usr/bin/stat -c '%a' -- "$current")"
    [[ "$owner" == "0" ]] || {
      printf '%s is not rooted entirely in root-owned paths: %s\n' "$label" "$current" >&2
      return 1
    }
    (( (8#$permissions & 8#022) == 0 )) || {
      printf '%s has a group/world-writable path component: %s\n' "$label" "$current" >&2
      return 1
    }
  done
}

assert_root_tree_safe() {
  local root="$1" label="$2" unsafe
  [[ -d "$root" && ! -L "$root" ]] || {
    printf '%s is not a no-follow directory: %s\n' "$label" "$root" >&2
    return 1
  }
  if ! unsafe="$(/usr/bin/find "$root" -xdev \
    \( ! -user root -o \( ! -type l -a -perm /022 \) \) -print -quit)"; then
    printf '%s could not be inspected completely\n' "$label" >&2
    return 1
  fi
  [[ -z "$unsafe" ]] || {
    printf '%s contains a non-root-owned or group/world-writable entry\n' "$label" >&2
    return 1
  }
}

prepare_empty_root_directory() {
  local directory="$1" label="$2" parent first_entry
  if [[ -e "$directory" || -L "$directory" ]]; then
    assert_root_safe_components "$directory" "$label"
    [[ -d "$directory" && ! -L "$directory" ]] || {
      printf '%s is not a no-follow directory: %s\n' "$label" "$directory" >&2
      return 1
    }
    if ! first_entry="$(/usr/bin/find "$directory" -mindepth 1 -maxdepth 1 \
      -print -quit)"; then
      printf '%s could not be inspected completely: %s\n' "$label" "$directory" >&2
      return 1
    fi
    [[ -z "$first_entry" ]] || {
      printf '%s must be empty; refusing stale build state: %s\n' "$label" "$directory" >&2
      return 1
    }
  else
    parent="$(/usr/bin/dirname -- "$directory")"
    assert_root_safe_components "$parent" "$label parent"
    /usr/bin/install -d -o root -g root -m 0755 -- "$directory"
    assert_root_safe_components "$directory" "$label"
  fi
}

env_bin="$(resolve_trusted_tool /usr/bin/env)"
git_bin="$(resolve_trusted_tool /usr/bin/git)"
gzip_bin="$(resolve_trusted_tool /usr/bin/gzip)"
bsdtar_bin="$(resolve_trusted_tool /usr/bin/bsdtar)"
makepkg_bin="$(resolve_trusted_tool /usr/bin/makepkg)"
mkarchiso_bin="$(resolve_trusted_tool /usr/bin/mkarchiso)"
mkosi_bin="$(resolve_trusted_tool /usr/bin/mkosi)"
ukify_bin="$(resolve_trusted_tool /usr/bin/ukify)"
repo_add_bin="$(resolve_trusted_tool /usr/bin/repo-add)"
python_bin="$(resolve_trusted_tool /usr/bin/python3)"
sha256sum_bin="$(resolve_trusted_tool /usr/bin/sha256sum)"
sort_bin="$(resolve_trusted_tool /usr/bin/sort)"
timeout_bin="$(resolve_trusted_tool /usr/bin/timeout)"
findmnt_bin="$(resolve_trusted_tool /usr/bin/findmnt)"
getent_bin="$(resolve_trusted_tool /usr/bin/getent)"
pacman_bin="$(resolve_trusted_tool /usr/bin/pacman)"
setpriv_bin="$(resolve_trusted_tool /usr/bin/setpriv)"
pgrep_bin="$(resolve_trusted_tool /usr/bin/pgrep)"
pkill_bin="$(resolve_trusted_tool /usr/bin/pkill)"
sleep_bin="$(resolve_trusted_tool /usr/bin/sleep)"
setsid_bin="$(resolve_trusted_tool /usr/bin/setsid)"
unshare_bin="$(resolve_trusted_tool /usr/bin/unshare)"
kill_bin="$(resolve_trusted_tool /usr/bin/kill)"
readonly env_bin git_bin gzip_bin bsdtar_bin makepkg_bin mkarchiso_bin mkosi_bin
readonly ukify_bin repo_add_bin python_bin sha256sum_bin sort_bin timeout_bin
readonly findmnt_bin getent_bin pacman_bin setpriv_bin pgrep_bin pkill_bin sleep_bin
readonly setsid_bin unshare_bin kill_bin

readonly -a disabled_ai_env=(
  AURASCAN_AI_ENABLED=0
  AURASCAN_INSTRUCTION_AI_ENABLED=0
  AURASCAN_INCIDENT_AI_ENABLED=0
  AURASCAN_RECOVERY_AI_ENABLED=0
)
readonly -a clean_root_env=(
  "$env_bin" -i
  PATH=/usr/bin:/bin
  HOME=/root
  USER=root
  LOGNAME=root
  LANG=C.UTF-8
  LC_ALL=C.UTF-8
  TZ=UTC
  PYTHONDONTWRITEBYTECODE=1
  "${disabled_ai_env[@]}"
)

assert_identity_unassigned() {
  local database="$1" identity="$2" label="$3" query_status
  if "${clean_root_env[@]}" "$getent_bin" "$database" "$identity" \
    >/dev/null 2>&1; then
    printf 'The fixed recovery package-build %s is assigned on this builder\n' \
      "$label" >&2
    return 1
  else
    query_status=$?
  fi
  (( query_status == 2 )) || {
    printf 'The fixed recovery package-build %s could not be queried reliably\n' \
      "$label" >&2
    return 1
  }
}

isolated_uid_process_state() {
  local query_status
  if "$pgrep_bin" -u "$isolated_build_uid" >/dev/null 2>&1; then
    return 0
  else
    query_status=$?
  fi
  if (( query_status == 1 )); then
    return 1
  fi
  printf 'The isolated package-build UID process state could not be queried reliably\n' >&2
  return 2
}

assert_root_safe_components "$repo_root" "AuraScan release checkout"
assert_root_tree_safe "$repo_root" "AuraScan release checkout"
if ! checkout_symlink="$(/usr/bin/find "$repo_root" -xdev -type l -print -quit)"; then
  printf 'Recovery ISO checkout symlink inspection failed\n' >&2
  exit 1
fi
[[ -z "$checkout_symlink" ]] || {
  printf 'Recovery ISO builds require a checkout without symlinks\n' >&2
  exit 1
}
if ! initial_git_status="$("${clean_root_env[@]}" "$git_bin" -C "$repo_root" \
  status --porcelain=v1 --untracked-files=all)"; then
  printf 'Recovery ISO checkout state could not be inspected\n' >&2
  exit 1
fi
[[ -z "$initial_git_status" ]] || {
  printf 'Recovery ISO builds require a clean committed worktree\n' >&2
  exit 1
}
if ! initial_ignored_state="$("${clean_root_env[@]}" "$git_bin" -C "$repo_root" \
  ls-files --others --ignored --exclude-standard)"; then
  printf 'Recovery ISO ignored-state inspection failed\n' >&2
  exit 1
fi
[[ -z "$initial_ignored_state" ]] || {
  printf 'Recovery ISO builds require a fresh checkout without ignored build state\n' >&2
  exit 1
}

readonly candidate_helper="$repo_root/packaging/recovery/recovery-build-helper.py"
"${clean_root_env[@]}" "$python_bin" -I -S "$candidate_helper" validate-candidate \
  --root "$repo_root" \
  --version "$expected_release_version" \
  --released-at "$expected_release_date"

if ! source_commit="$("${clean_root_env[@]}" "$git_bin" -C "$repo_root" \
  rev-parse --verify 'HEAD^{commit}')"; then
  printf 'Recovery source commit could not be resolved\n' >&2
  exit 1
fi
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'Recovery source commit is not an exact lowercase object identity\n' >&2
  exit 1
}
readonly source_commit
if ! source_date_epoch="$("${clean_root_env[@]}" "$git_bin" -C "$repo_root" \
  show -s --format=%ct "$source_commit")"; then
  printf 'Recovery source date could not be resolved\n' >&2
  exit 1
fi
[[ "$source_date_epoch" =~ ^[1-9][0-9]*$ ]] || {
  printf 'Recovery source date is invalid\n' >&2
  exit 1
}
readonly source_date_epoch
readonly pkgver="$expected_release_version"
readonly pkgrel=1

missing_dependencies=""
if ! missing_dependencies="$("${clean_root_env[@]}" "$pacman_bin" -T -- \
  base-devel python hicolor-icon-theme python-build python-installer \
  python-setuptools python-wheel python-pytest)"; then
  printf 'Install the trusted recovery build dependencies before running the builder: %s\n' \
    "${missing_dependencies//$'\n'/ }" >&2
  exit 1
fi

if [[ -e "$build_base" || -L "$build_base" ]]; then
  assert_root_safe_components "$build_base" "Recovery builder base"
  [[ -d "$build_base" && ! -L "$build_base" ]] || {
    printf 'Recovery builder base is not a no-follow directory\n' >&2
    exit 1
  }
else
  assert_root_safe_components "$(/usr/bin/dirname -- "$build_base")" \
    "Recovery builder base parent"
  /usr/bin/install -d -o root -g root -m 0711 -- "$build_base"
fi
/usr/bin/chmod 0711 -- "$build_base"
assert_root_safe_components "$build_base" "Recovery builder base"

output_raw="${1:-$build_base/release-$pkgver}"
output="$(/usr/bin/realpath -m -- "$output_raw")"
case "$output/" in
  "$build_base"/*/) ;;
  *)
    printf 'Recovery output must be a child of the root-owned builder base: %s\n' \
      "$build_base" >&2
    exit 1
    ;;
esac
prepare_empty_root_directory "$output" "Recovery output directory"

work="$(/usr/bin/mktemp -d --tmpdir="$build_base" \
  "recovery-archiso-$pkgver.XXXXXXXX")"
readonly output work
/usr/bin/chown root:root -- "$work"
/usr/bin/chmod 0711 -- "$work"
assert_root_safe_components "$work" "Archiso work directory"
case "$output/" in "$work/"*) printf 'Recovery output must not be inside work\n' >&2; exit 1 ;; esac
case "$work/" in "$output/"*) printf 'Archiso work must not be inside output\n' >&2; exit 1 ;; esac

archiso_base="$(/usr/bin/readlink -e -- /usr/share/archiso/configs/releng)" || {
  printf 'Archiso releng profile is unavailable\n' >&2
  exit 1
}
readonly archiso_base
assert_root_safe_components "$archiso_base" "Archiso releng profile"
assert_root_tree_safe "$archiso_base" "Archiso releng profile"

readonly profile="$work/profile"
readonly package_repo="$work/package-repo"
readonly package_cache="$work/package-cache"
readonly source_snapshot="$work/source-snapshot"
readonly package_stage="$work/isolated-package-build"
readonly package_build="$package_stage/build"
readonly build_home="$package_stage/home"
/usr/bin/install -d -o root -g root -m 0755 -- \
  "$profile" "$package_repo" "$package_cache" "$source_snapshot"
/usr/bin/install -d -o "$isolated_build_uid" -g "$isolated_build_gid" -m 0700 -- \
  "$package_stage" "$package_build" "$build_home"

assert_identity_unassigned passwd "$isolated_build_uid" UID
assert_identity_unassigned group "$isolated_build_gid" GID
if isolated_uid_process_state; then
  printf 'The isolated recovery package-build UID is already active\n' >&2
  exit 1
else
  process_state=$?
fi
(( process_state == 1 )) || {
  printf 'The isolated recovery package-build UID could not be proven idle\n' >&2
  exit 1
}

isolated_uid_active=0
terminate_isolated_uid() {
  local attempt
  if (( isolated_uid_active )); then
    "$pkill_bin" -KILL -u "$isolated_build_uid" >/dev/null 2>&1 || true
    for attempt in {1..50}; do
      if isolated_uid_process_state; then
        :
      else
        process_state=$?
        (( process_state == 1 )) || return 1
        isolated_uid_active=0
        return 0
      fi
      "$sleep_bin" 0.1
    done
    printf 'Could not retire all isolated package-build processes\n' >&2
    return 1
  fi
}
handle_signal() {
  local status="$1"
  trap - HUP INT TERM
  terminate_isolated_uid || true
  exit "$status"
}
trap 'terminate_isolated_uid || true' EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

readonly -a clean_package_env=(
  "$env_bin" -i
  PATH=/usr/bin:/bin
  HOME="$build_home"
  USER=aurascan-recovery-build
  LOGNAME=aurascan-recovery-build
  LANG=C.UTF-8
  LC_ALL=C.UTF-8
  TZ=UTC
  PYTHONDONTWRITEBYTECODE=1
  SOURCE_DATE_EPOCH="$source_date_epoch"
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_NOSYSTEM=1
  BUILDDIR="$package_build/makepkg-build"
  SRCDEST="$package_build/sources"
  SRCPKGDEST="$package_build/source-packages"
  PKGDEST="$package_build/packages"
  LOGDEST="$package_build/logs"
  "${disabled_ai_env[@]}"
)

archive="$package_build/AuraScan-$pkgver.tar.gz"
"${clean_root_env[@]}" "$git_bin" -C "$repo_root" archive \
  --format=tar --prefix="AuraScan-$pkgver/" "$source_commit" | "$gzip_bin" -n > "$archive"
"${clean_root_env[@]}" "$bsdtar_bin" -xzf "$archive" -C "$source_snapshot"
snapshot_root="$source_snapshot/AuraScan-$pkgver"
[[ -d "$snapshot_root" && ! -L "$snapshot_root" ]] || {
  printf 'Committed source snapshot could not be captured safely\n' >&2
  exit 1
}
readonly snapshot_root
if ! snapshot_symlink="$(/usr/bin/find "$snapshot_root" -type l -print -quit)"; then
  printf 'Exact recovery candidate symlink inspection failed\n' >&2
  exit 1
fi
[[ -z "$snapshot_symlink" ]] || {
  printf 'Exact recovery candidate snapshot must not contain symlinks\n' >&2
  exit 1
}
# Git archives intentionally restore ordinary tracked files and directories
# with group-write bits.  The snapshot is root-created from the exact commit
# and contains no links at this point, so remove only group/world write access
# while preserving every recorded executable bit before root consumes it.
/usr/bin/chmod -R go-w -- "$snapshot_root"
assert_root_tree_safe "$snapshot_root" "Exact recovery candidate snapshot"
"${clean_root_env[@]}" "$python_bin" -I -S \
  "$snapshot_root/packaging/recovery/recovery-build-helper.py" validate-candidate \
  --root "$snapshot_root" \
  --version "$expected_release_version" \
  --released-at "$expected_release_date"
profile_source="$snapshot_root/packaging/recovery/archiso"
if ! profile_symlink="$(/usr/bin/find "$profile_source" -type l -print -quit)"; then
  printf 'AuraScan Archiso overlay symlink inspection failed\n' >&2
  exit 1
fi
[[ -z "$profile_symlink" ]] || {
  printf 'AuraScan Archiso overlay must not contain symlinks\n' >&2
  exit 1
}

/usr/bin/cp -a -- "$archiso_base"/. "$profile"/
/usr/bin/cp -a -- "$profile_source"/airootfs/. "$profile/airootfs"/
/usr/bin/install -d -o root -g root -m 0755 -- \
  "$profile/airootfs/etc/systemd/system/multi-user.target.wants"
/usr/bin/ln -sfn /usr/lib/systemd/system/aurascan-recovery.service \
  "$profile/airootfs/etc/systemd/system/multi-user.target.wants/aurascan-recovery.service"
/usr/bin/ln -sfn /usr/lib/systemd/system/aurascan-recovery-smoke-marker.service \
  "$profile/airootfs/etc/systemd/system/multi-user.target.wants/aurascan-recovery-smoke-marker.service"
/usr/bin/ln -sfn /dev/null "$profile/airootfs/etc/systemd/system/getty@tty1.service"
/usr/bin/grep -Fq '@AURASCAN_VERSION@' "$profile/airootfs/etc/issue" || {
  printf 'Recovery issue banner lacks its version placeholder\n' >&2
  exit 1
}
/usr/bin/sed -i "s/@AURASCAN_VERSION@/$pkgver/g" "$profile/airootfs/etc/issue"
if /usr/bin/grep -Fq '@AURASCAN_VERSION@' "$profile/airootfs/etc/issue"; then
  printf 'Recovery issue banner version substitution was incomplete\n' >&2
  exit 1
else
  grep_status=$?
  (( grep_status == 1 )) || {
    printf 'Recovery issue banner could not be verified after substitution\n' >&2
    exit 1
  }
fi
/usr/bin/cat "$profile_source/profiledef.sh" >> "$profile/profiledef.sh"
/usr/bin/cp -- "$profile_source/pacman.conf" "$profile/pacman.conf"
/usr/bin/sed -i "/^\[options\]$/a CacheDir = $package_cache" "$profile/pacman.conf"
/usr/bin/cat "$profile_source/packages.x86_64" >> "$profile/packages.x86_64"
/usr/bin/sed -i -e '/^linux$/d' -e '/^broadcom-wl$/d' "$profile/packages.x86_64"
/usr/bin/rm -f -- "$profile/airootfs/etc/mkinitcpio.d/linux.preset"
/usr/bin/find "$profile/syslinux" "$profile/efiboot" "$profile/grub" -type f \
  -exec /usr/bin/sed -E -i \
  -e 's#vmlinuz-linux([[:space:]]|$)#vmlinuz-linux-lts\1#g' \
  -e 's#initramfs-linux\.img([[:space:]]|$)#initramfs-linux-lts.img\1#g' {} +
/usr/bin/find "$profile/syslinux" "$profile/efiboot" "$profile/grub" -type f \
  -exec /usr/bin/sed -E -i \
  -e '/^[[:space:]]*(APPEND|options)[[:space:]].*archisobasedir=/ s#$# console=tty0 console=ttyS0,115200n8#' \
  -e '/^[[:space:]]*linux[[:space:]].*vmlinuz.*archisobasedir=/ s#$# console=tty0 console=ttyS0,115200n8#' {} +
if /usr/bin/grep -R -E \
  'vmlinuz-linux([[:space:]]|$)|initramfs-linux\.img([[:space:]]|$)' \
  "$profile/syslinux" "$profile/efiboot" "$profile/grub"; then
  printf 'Recovery bootloader configuration still references the removed standard kernel\n' >&2
  exit 1
else
  grep_status=$?
  (( grep_status == 1 )) || {
    printf 'Recovery bootloader configuration could not be inspected completely\n' >&2
    exit 1
  }
fi
LC_ALL=C "$sort_bin" -u -o "$profile/packages.x86_64" "$profile/packages.x86_64"

/usr/bin/cp -- "$snapshot_root/packaging/arch/PKGBUILD" \
  "$snapshot_root/packaging/arch/aurascan.install" "$package_build"/
archive_sha_line="$("$sha256sum_bin" "$archive")"
archive_sha="${archive_sha_line%% *}"
[[ "$archive_sha" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'Could not hash the committed AuraScan source archive\n' >&2
  exit 1
}
/usr/bin/sed -i \
  -e "s|^source=.*|source=('AuraScan-$pkgver.tar.gz')|" \
  -e "s|^sha256sums=.*|sha256sums=('$archive_sha')|" \
  "$package_build/PKGBUILD"
/usr/bin/chown -R "$isolated_build_uid:$isolated_build_gid" -- "$package_stage"
/usr/bin/chmod 0700 -- "$package_stage" "$package_build" "$build_home"

isolated_uid_active=1
makepkg_log="$work/makepkg.log"
makepkg_output_exceeded=0
/usr/bin/install -o root -g root -m 0600 /dev/null "$makepkg_log"
(
  ulimit -f "$((512 * 1024))"
  ulimit -n 1024
  ulimit -u 2048
  cd -- "$package_build"
  exec "$setsid_bin" "$timeout_bin" --signal=TERM --kill-after=10s 3600s \
    "$unshare_bin" --net --fork --kill-child=KILL --forward-signals -- \
      "$setpriv_bin" \
        --reuid="$isolated_build_uid" \
        --regid="$isolated_build_gid" \
        --clear-groups \
        --no-new-privs \
        -- "${clean_package_env[@]}" "$makepkg_bin" \
          --clean --cleanbuild --nodeps --noconfirm --config /etc/makepkg.conf
) > "$makepkg_log" 2>&1 &
makepkg_runner_pid=$!
while "$kill_bin" -0 "$makepkg_runner_pid" >/dev/null 2>&1; do
  makepkg_log_size="$(/usr/bin/stat -c '%s' -- "$makepkg_log")"
  if (( makepkg_log_size >= 16 * 1024 * 1024 )); then
    makepkg_output_exceeded=1
    "$kill_bin" -TERM -- "-$makepkg_runner_pid" >/dev/null 2>&1 || true
    break
  fi
  "$sleep_bin" 0.2
done
if wait "$makepkg_runner_pid"; then
  makepkg_status=0
else
  makepkg_status=$?
fi
terminate_isolated_uid
makepkg_log_size="$(/usr/bin/stat -c '%s' -- "$makepkg_log")"
(( makepkg_status == 0 && makepkg_output_exceeded == 0 && \
   makepkg_log_size < 16 * 1024 * 1024 )) || {
  printf 'Isolated AuraScan package build failed or reached a resource bound\n' >&2
  exit 1
}
/usr/bin/chown -R root:root -- "$package_stage"
/usr/bin/chmod -R go-w -- "$package_stage"
assert_root_tree_safe "$package_stage" "Reclaimed AuraScan package build"

shopt -s nullglob
package_candidates=("$package_build/packages/aurascan-$pkgver-$pkgrel-any.pkg.tar."*)
(( ${#package_candidates[@]} == 1 )) || {
  printf 'Expected exactly one AuraScan Arch package, found %s\n' \
    "${#package_candidates[@]}" >&2
  exit 1
}
package_candidate="${package_candidates[0]}"
[[ -f "$package_candidate" && ! -L "$package_candidate" ]] || {
  printf 'AuraScan package output is not a no-follow regular file\n' >&2
  exit 1
}
package_sha_line="$("$sha256sum_bin" "$package_candidate")"
package_sha="${package_sha_line%% *}"
package_name="${package_candidate##*/}"
/usr/bin/install -o root -g root -m 0644 -- "$package_candidate" \
  "$package_repo/$package_name"
"${clean_root_env[@]}" "$repo_add_bin" "$package_repo/aurascan-recovery.db.tar.zst" \
  "$package_repo/$package_name"
copied_package_sha_line="$("$sha256sum_bin" "$package_repo/$package_name")"
[[ "${copied_package_sha_line%% *}" == "$package_sha" ]] || {
  printf 'AuraScan package changed while entering the root-owned local repository\n' >&2
  exit 1
}
package_repo_uri="$("${clean_root_env[@]}" "$python_bin" -I -S -c \
  'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve().as_uri())' \
  "$package_repo")"
"${clean_root_env[@]}" "$python_bin" -I -S - \
  "$profile/pacman.conf" "$package_repo_uri" <<'PY'
import os
import re
import stat
import sys

path, repository_uri = sys.argv[1:]
metadata = os.lstat(path)
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("unsafe Archiso pacman configuration")
with open(path, "r", encoding="utf-8", errors="strict", newline="") as handle:
    original = handle.read()
needle = "\n[core]\n"
if original.count(needle) != 1 or "[aurascan-recovery]" in original:
    raise SystemExit("unexpected Archiso repository configuration")
block = (
    "\n[aurascan-recovery]\n"
    "SigLevel = Optional TrustAll\n"
    "Server = {}\n".format(repository_uri)
)
updated = original.replace(needle, block + needle, 1)
headers = re.findall(r"^\[([^]]+)\]$", updated, flags=re.MULTILINE)
if headers[:3] != ["options", "aurascan-recovery", "core"]:
    raise SystemExit("local AuraScan repository does not precede official repositories")
flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
    handle.write(updated)
with open(path, "r", encoding="utf-8", errors="strict", newline="") as handle:
    if handle.read() != updated:
        raise SystemExit("Archiso repository configuration changed unexpectedly")
PY

bad_modalias_line='        find "${pacstrap_dir}/usr/lib/modules" -name '\''modules.alias'\'' -print -exec gzip -cn9 '\''{}'\'' '\'';'\'' -quit > \'
fixed_modalias_line='        find "${pacstrap_dir}/usr/lib/modules" -name '\''modules.alias'\'' -exec gzip -cn9 '\''{}'\'' '\'';'\'' -quit > \'
mkarchiso_runner="$mkarchiso_bin"
if bad_modalias_count="$(/usr/bin/grep -Fxc -- \
  "$bad_modalias_line" "$mkarchiso_bin")"; then
  :
else
  grep_status=$?
  (( grep_status == 1 )) || {
    printf 'Installed mkarchiso could not be inspected for the Archiso 89 correction\n' >&2
    exit 1
  }
  bad_modalias_count=0
fi
if modalias_reference_count="$(/usr/bin/grep -Fc -- \
  'modules.alias' "$mkarchiso_bin")"; then
  :
else
  grep_status=$?
  (( grep_status == 1 )) || {
    printf 'Installed mkarchiso module-alias references could not be inspected\n' >&2
    exit 1
  }
  modalias_reference_count=0
fi
archiso_package="$("${clean_root_env[@]}" "$pacman_bin" -Q archiso)"
if [[ "$archiso_package" =~ ^archiso[[:space:]]89-[0-9]+$ ]]; then
  [[ "$bad_modalias_count" == "1" && "$modalias_reference_count" == "1" ]] || {
    printf 'Archiso 89 has an unexpected modules.alias implementation\n' >&2
    exit 1
  }
  /usr/bin/install -d -o root -g root -m 0755 -- "$work/trusted-tools"
  mkarchiso_runner="$work/trusted-tools/mkarchiso-archiso89"
  /usr/bin/install -o root -g root -m 0755 -- "$mkarchiso_bin" "$mkarchiso_runner"
  "${clean_root_env[@]}" "$python_bin" -I -S -c '
import os, stat, sys
path, before, after = sys.argv[1:]
metadata = os.lstat(path)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
    raise SystemExit("unsafe Archiso compatibility target")
with open(path, "r", encoding="utf-8", errors="strict", newline="") as handle:
    lines = handle.readlines()
old = before + "\n"
new = after + "\n"
if lines.count(old) != 1 or new in lines:
    raise SystemExit("unexpected Archiso 89 modules.alias implementation")
expected = [new if line == old else line for line in lines]
flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags)
with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
    handle.writelines(expected)
with open(path, "r", encoding="utf-8", errors="strict", newline="") as handle:
    if handle.readlines() != expected:
        raise SystemExit("Archiso compatibility correction changed unexpectedly")
' "$mkarchiso_runner" "$bad_modalias_line" "$fixed_modalias_line"
else
  if /usr/bin/grep -Fq -- \
    "modules.alias' -print -exec gzip" "$mkarchiso_bin"; then
    unexpected_modalias_pattern=1
  else
    grep_status=$?
    (( grep_status == 1 )) || {
      printf 'Installed mkarchiso could not be inspected for unexpected module-alias logic\n' >&2
      exit 1
    }
    unexpected_modalias_pattern=0
  fi
fi
if [[ ! "$archiso_package" =~ ^archiso[[:space:]]89-[0-9]+$ ]] && \
   [[ "$bad_modalias_count" != "0" || "$unexpected_modalias_pattern" == "1" ]]; then
  printf 'Installed mkarchiso has an unexpected modules.alias implementation\n' >&2
  exit 1
fi
readonly mkarchiso_runner

assert_root_tree_safe "$profile" "Root-consumed Archiso profile"
assert_root_tree_safe "$package_repo" "Root-consumed local package repository"
assert_root_tree_safe "$package_cache" "Root-consumed package cache"
if isolated_uid_process_state; then
  printf 'An isolated package-build process survived reclamation\n' >&2
  exit 1
else
  process_state=$?
fi
(( process_state == 1 )) || {
  printf 'The isolated package-build UID could not be proven retired\n' >&2
  exit 1
}

readonly -a archiso_env=(
  "$env_bin" -i
  PATH=/usr/bin:/bin
  HOME=/root
  USER=root
  LOGNAME=root
  LANG=C.UTF-8
  LC_ALL=C.UTF-8
  TZ=UTC
  SOURCE_DATE_EPOCH="$source_date_epoch"
  AURASCAN_RECOVERY_VERSION="$pkgver"
  "${disabled_ai_env[@]}"
)
"${archiso_env[@]}" "$mkarchiso_runner" -v -w "$work" -o "$output" "$profile"

expected_iso="$output/aurascan-recovery-$pkgver-x86_64.iso"
iso_candidates=("$output"/*.iso)
(( ${#iso_candidates[@]} == 1 )) || {
  printf 'Expected exactly one recovery ISO, found %s\n' "${#iso_candidates[@]}" >&2
  exit 1
}
[[ "${iso_candidates[0]}" == "$expected_iso" && -f "$expected_iso" && ! -L "$expected_iso" ]] || {
  printf 'Archiso did not produce the exact expected release filename\n' >&2
  exit 1
}
iso_owner="$(/usr/bin/stat -c '%u' -- "$expected_iso")"
iso_mode="$(/usr/bin/stat -c '%a' -- "$expected_iso")"
[[ "$iso_owner" == "0" && "$iso_mode" == "644" ]] || {
  printf 'Recovery ISO must remain a root-owned 0644 artifact\n' >&2
  exit 1
}
iso_size="$(/usr/bin/stat -c '%s' -- "$expected_iso")"
(( iso_size < release_asset_limit )) || {
  printf 'Recovery ISO is %s bytes; it must be strictly smaller than 2147483648 bytes\n' \
    "$iso_size" >&2
  exit 1
}

modalias="$work/iso/boot/syslinux/hdt/modalias.gz"
if [[ -f "$modalias" ]] && ! "$gzip_bin" -t "$modalias"; then
  printf 'Archiso produced a malformed SYSLINUX module-alias payload\n' >&2
  exit 1
fi
installed_packages="$work/iso/aurascan/pkglist.x86_64.txt"
[[ -f "$installed_packages" && ! -L "$installed_packages" ]] || {
  printf 'Archiso package manifest was not produced as a regular file\n' >&2
  exit 1
}
[[ "$(/usr/bin/grep -Fxc -- "aurascan $pkgver-$pkgrel" "$installed_packages")" == "1" ]] || {
  printf 'Archiso did not install the exact release-candidate AuraScan package\n' >&2
  exit 1
}
LC_ALL=C "$sort_bin" -u -- "$installed_packages" > "$expected_iso.packages.txt"
[[ -s "$expected_iso.packages.txt" ]] || {
  printf 'Archiso package manifest is empty\n' >&2
  exit 1
}
iso_sha_line="$("$sha256sum_bin" "$expected_iso")"
iso_sha="${iso_sha_line%% *}"
printf '%s  %s\n' "$iso_sha" "${expected_iso##*/}" > "$expected_iso.sha256"
/usr/bin/chmod 0644 -- "$expected_iso.sha256" "$expected_iso.packages.txt"
output_entries=("$output"/* "$output"/.[!.]* "$output"/..?*)
(( ${#output_entries[@]} == 3 )) || {
  printf 'Recovery output must contain exactly the ISO, checksum, and package manifest\n' >&2
  exit 1
}
for output_entry in "${output_entries[@]}"; do
  case "$output_entry" in
    "$expected_iso"|"$expected_iso.sha256"|"$expected_iso.packages.txt") ;;
    *) printf 'Recovery output contains an unexpected release asset\n' >&2; exit 1 ;;
  esac
done

validation_helper="$snapshot_root/packaging/recovery/recovery-build-helper.py"
"${archiso_env[@]}" "$python_bin" -I -S "$validation_helper" build-validation-uki \
  --snapshot "$snapshot_root" \
  --work "$work" \
  --version "$pkgver" \
  --source-commit "$source_commit" \
  --source-date-epoch "$source_date_epoch" \
  --mkosi "$mkosi_bin" \
  --ukify "$ukify_bin"
validation_uki="$work/validation-uki/aurascan-recovery-$pkgver-$source_commit-validation-unsigned.efi"
validation_uki_sidecar="$validation_uki.sha256"
[[ -f "$validation_uki" && ! -L "$validation_uki" && \
   -f "$validation_uki_sidecar" && ! -L "$validation_uki_sidecar" ]] || {
  printf 'Exact-candidate validation UKI or its checksum sidecar is unavailable\n' >&2
  exit 1
}
validation_uki_sha_line="$(<"$validation_uki_sidecar")"
validation_uki_sha="${validation_uki_sha_line%% *}"
[[ "$validation_uki_sha_line" == \
   "$validation_uki_sha  ${validation_uki##*/}" && \
   "$validation_uki_sha" =~ ^[0-9a-f]{64}$ && \
   "$("$sha256sum_bin" "$validation_uki")" == "$validation_uki_sha  $validation_uki" ]] || {
  printf 'Validation UKI checksum sidecar does not bind the exact basename and bytes\n' >&2
  exit 1
}
assert_root_tree_safe "$work/validation-uki" "Exact-candidate validation UKI"

expanded_root="$work/x86_64/airootfs"
[[ -d "$expanded_root" && ! -L "$expanded_root" ]] || {
  printf 'Archiso expanded root is unavailable for the privacy audit\n' >&2
  exit 1
}
mount_snapshot="$work/current-mount-table.json"
[[ ! -e "$mount_snapshot" && ! -L "$mount_snapshot" ]] || {
  printf 'Mount-table snapshot destination already exists; refusing artifact audit\n' >&2
  exit 1
}
/usr/bin/install -o root -g root -m 0600 /dev/null "$mount_snapshot"
if ! (
  ulimit -f 8192 || exit 1
  exec "${clean_root_env[@]}" "$timeout_bin" \
    --signal=TERM --kill-after=5s 30s "$findmnt_bin" \
    --kernel=mountinfo --json --list --output TARGET
) >"$mount_snapshot" 2>/dev/null; then
  printf 'Current mount table could not be captured completely; refusing artifact audit\n' >&2
  exit 1
fi
/usr/bin/chmod 0400 -- "$mount_snapshot"
"${clean_root_env[@]}" "$python_bin" -I -S \
  "$snapshot_root/packaging/recovery/recovery-build-helper.py" verify-no-mounts \
  --snapshot "$mount_snapshot" \
  --root "$expanded_root"
audit_script="$snapshot_root/packaging/recovery/audit-artifacts.py"
[[ -f "$audit_script" && ! -L "$audit_script" ]] || {
  printf 'Committed recovery artifact auditor is unavailable\n' >&2
  exit 1
}
"${archiso_env[@]}" "$timeout_bin" 1200s "$bsdtar_bin" \
  --one-file-system --format pax -cf - -C "$expanded_root" . | \
  "${archiso_env[@]}" "$python_bin" -I -S "$audit_script" \
    --iso "$expected_iso" \
    --version "$pkgver" \
    --scan-root "$profile/airootfs" \
    --scan-root "$package_stage" \
    --scan-root "$package_repo" \
    --scan-root "$work/iso" \
    --scan-root "$work/validation-uki" \
    --forbid "$repo_root" \
    --forbid "$work" \
    --tar-stream

final_commit="$("${clean_root_env[@]}" "$git_bin" -C "$repo_root" \
  rev-parse --verify 'HEAD^{commit}')"
[[ "$final_commit" == "$source_commit" ]] || {
  printf 'Repository HEAD changed during the recovery build\n' >&2
  exit 1
}
if ! final_git_status="$("${clean_root_env[@]}" "$git_bin" -C "$repo_root" \
  status --porcelain=v1 --untracked-files=all)"; then
  printf 'Final recovery checkout state could not be inspected\n' >&2
  exit 1
fi
[[ -z "$final_git_status" ]] || {
  printf 'Tracked repository state changed during the recovery build\n' >&2
  exit 1
}
if ! final_ignored_state="$("${clean_root_env[@]}" "$git_bin" -C "$repo_root" \
  ls-files --others --ignored --exclude-standard)"; then
  printf 'Final recovery ignored-state inspection failed\n' >&2
  exit 1
fi
[[ -z "$final_ignored_state" ]] || {
  printf 'Ignored build state appeared in the release checkout during the build\n' >&2
  exit 1
}

validation_attestation="$work/recovery-validation-attestation.json"
"${archiso_env[@]}" "$python_bin" -I -S "$validation_helper" \
  write-validation-attestation \
  --snapshot "$snapshot_root" \
  --iso "$expected_iso" \
  --validation-uki "$validation_uki" \
  --destination "$validation_attestation" \
  --version "$pkgver" \
  --source-commit "$source_commit"
[[ -f "$validation_attestation" && ! -L "$validation_attestation" && \
   "$(/usr/bin/stat -c '%u:%a' -- "$validation_attestation")" == "0:400" ]] || {
  printf 'Root-only recovery validation attestation is unavailable\n' >&2
  exit 1
}

printf 'Built audited hybrid BIOS/UEFI recovery image: %s\n' "$expected_iso"
printf 'Release-candidate source commit: %s\n' "$source_commit"
printf 'Validation UKI for QEMU (not a release asset): %s\n' "$validation_uki"
printf 'Validation UKI SHA-256: %s\n' "$validation_uki_sha"
printf 'Trusted validation harness root: %s\n' "$snapshot_root"
printf 'Private validation attestation: %s\n' "$validation_attestation"
printf 'Retained root-owned Archiso work state for release validation: %s\n' "$work"
printf "RECOVERY_ISO='%s'\n" "$expected_iso"
printf "RECOVERY_UKI='%s'\n" "$validation_uki"
printf "RECOVERY_HARNESS_ROOT='%s'\n" "$snapshot_root"
printf "RECOVERY_ATTESTATION='%s'\n" "$validation_attestation"
