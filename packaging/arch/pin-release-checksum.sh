#!/usr/bin/env bash
# Pin the exact public GitHub source archive checksum into packaging/arch.
#
# Run only after the matching annotated tag is public and HEAD is that tag
# commit. The script refuses rather than guessing while the tag is absent.
set -euo pipefail
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
PKGBUILD="$SCRIPT_DIR/PKGBUILD"
SRCINFO="$SCRIPT_DIR/.SRCINFO"

pkgver="$(awk -F= '$1 == "pkgver" { gsub(/"/, "", $2); print $2; exit }' "$PKGBUILD")"
url="$(awk -F= '$1 == "url" { gsub(/"/, "", $2); print $2; exit }' "$PKGBUILD")"
if [[ -z "$pkgver" || -z "$url" ]]; then
    printf 'refusing: PKGBUILD has no pkgver or url\n' >&2
    exit 2
fi
tag="v$pkgver"
archive_url="$url/archive/refs/tags/$tag.tar.gz"

if ! git -C "$REPO_ROOT" ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    printf 'refusing: public tag %s is not on origin; publish it first\n' "$tag" >&2
    exit 2
fi

tag_commit="$(git -C "$REPO_ROOT" ls-remote --tags origin "refs/tags/$tag^{}" | awk '{print $1}')"
head_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
if [[ -z "$tag_commit" || "$tag_commit" != "$head_commit" ]]; then
    printf 'refusing: HEAD %s is not the public tag commit %s\n' "$head_commit" "${tag_commit:-missing}" >&2
    exit 3
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/aurascan-pin.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
archive="$tmp/aurascan-$pkgver.tar.gz"

printf 'Downloading %s\n' "$archive_url"
curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 --max-time 120 --max-filesize 104857600 \
    --output "$archive" "$archive_url"

tar -tzf "$archive" > "$tmp/listing"
first_path="$(head -n 1 "$tmp/listing")"
case "$first_path" in
    "AuraScan-$pkgver/"*) ;;
    *)
        printf 'refusing: archive does not start with AuraScan-%s/ (saw %s)\n' "$pkgver" "$first_path" >&2
        exit 4
        ;;
esac

hash="$(sha256sum "$archive" | awk '{print $1}')"
if [[ ! "$hash" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'refusing: sha256sum produced an invalid digest\n' >&2
    exit 4
fi

if [[ "$(grep -c "^sha256sums=('SKIP')$" "$PKGBUILD")" -ne 1 ]]; then
    printf 'refusing: expected exactly one sha256sums=(\x27SKIP\x27) line in %s\n' "$PKGBUILD" >&2
    exit 5
fi

sed -i "s/^sha256sums=('SKIP')$/sha256sums=('$hash')/" "$PKGBUILD"

mkdir -p "$tmp/home"
chmod 700 "$tmp/home"
(
    cd "$SCRIPT_DIR"
    env -i PATH=/usr/bin:/bin HOME="$tmp/home" USER=aurascan-release \
        LOGNAME=aurascan-release LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
        /usr/bin/makepkg --config /etc/makepkg.conf --printsrcinfo > "$tmp/SRCINFO"
)
mv "$tmp/SRCINFO" "$SRCINFO"

if ! grep -q "sha256sums=('$hash')" "$PKGBUILD"; then
    printf 'refusing: PKGBUILD still lacks the pinned digest\n' >&2
    exit 6
fi
if ! grep -q "sha256sums = $hash" "$SRCINFO"; then
    printf 'refusing: .SRCINFO still lacks the pinned digest\n' >&2
    exit 6
fi
if grep -q "^sha256sums=('SKIP')$" "$PKGBUILD" || \
   grep -q "^[[:space:]]*sha256sums = SKIP$" "$SRCINFO"; then
    printf 'refusing: the checksum placeholder remains after pinning\n' >&2
    exit 6
fi

printf 'Pinned %s\n  archive: %s\n  sha256: %s\n  files: %s, %s\n' \
    "$tag" "$archive_url" "$hash" "$PKGBUILD" "$SRCINFO"
