#!/usr/bin/env bash
# Generate and validate one ConMan Sparkle appcast from one published DMG.
#
# The release workflow invokes this after the DMG and checksum have been
# uploaded (or stages the exact same bytes for a final pre-upload check). The
# appcast is emitted last and is never allowed to reference a local path or a
# missing/mismatched archive.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
channel=""
release_tag=""
version=""
revision=""
dmg=""
appcast=""
sparkle_dir="${CONMAN_SPARKLE_DIR:-}"

usage() {
    cat <<'EOF'
Usage: generate-appcast.sh --channel stable|dev --release-tag TAG \
       --version SEMVER --revision N --dmg FILE --output FILE \
       [--sparkle-dir SPARKLE.framework]

CONMAN_SPARKLE_ED25519_PRIVATE_KEY must contain the Sparkle private key in the
format accepted by Sparkle 2.9.4's --ed-key-file - option. It is read through
stdin and is never written to a repository, artifact, or log.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --channel) channel=$2; shift 2 ;;
        --release-tag) release_tag=$2; shift 2 ;;
        --version) version=$2; shift 2 ;;
        --revision) revision=$2; shift 2 ;;
        --dmg) dmg=$2; shift 2 ;;
        --output) appcast=$2; shift 2 ;;
        --sparkle-dir) sparkle_dir=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$channel" == stable || "$channel" == dev ]] || { echo "--channel must be stable or dev" >&2; exit 2; }
[[ -n "$release_tag" && "$release_tag" != *[[:space:]/]* ]] || { echo "invalid --release-tag" >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-].*)?$ ]] || { echo "invalid --version" >&2; exit 2; }
[[ "$revision" =~ ^[1-9][0-9]*$ ]] || { echo "--revision must be a nonzero integer" >&2; exit 2; }
[[ -f "$dmg" ]] || { echo "DMG not found: $dmg" >&2; exit 1; }
[[ -n "$appcast" ]] || { echo "--output is required" >&2; exit 2; }
[[ -n "${CONMAN_SPARKLE_ED25519_PRIVATE_KEY:-}" ]] || {
    echo "CONMAN_SPARKLE_ED25519_PRIVATE_KEY is required to sign appcast output" >&2
    exit 1
}
for tool_name in ditto hdiutil plutil xmllint stat; do
    command -v "$tool_name" >/dev/null || {
        echo "Required macOS appcast tool not found: $tool_name" >&2
        exit 1
    }
done

if [[ -z "$sparkle_dir" ]]; then
    fetch_result=$("$script_dir/fetch-sparkle.sh" --output-dir "$(dirname "$appcast")/.sparkle")
    sparkle_dir=$(printf '%s\n' "$fetch_result" | sed -n 's/^SPARKLE_DIR=//p')
fi
tool="$(dirname "$sparkle_dir")/bin/generate_appcast"
[[ -x "$tool" ]] || { echo "Sparkle 2.9.4 generate_appcast tool not found" >&2; exit 1; }

case "$channel:$release_tag:$version" in
    stable:*-[0-9A-Za-z]*) echo "stable appcast cannot contain a prerelease version" >&2; exit 1 ;;
    dev:dev:*-dev.*) ;;
    dev:dev:*) echo "dev appcast requires a -dev.<revision> version" >&2; exit 1 ;;
    stable:*) ;;
    dev:*) echo "dev appcast must use the rolling dev release tag" >&2; exit 1 ;;
esac

mkdir -p "$(dirname "$appcast")"
work=$(mktemp -d "${TMPDIR:-/tmp}/conman-appcast.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
archives="$work/archives"
mkdir -p "$archives"
dmg_name=$(basename "$dmg")
ditto "$dmg" "$archives/$dmg_name"

mount_point="$work/mount"
mkdir -p "$mount_point"
hdiutil attach -quiet -readonly -nobrowse -mountpoint "$mount_point" "$dmg"
mounted=1
cleanup_mount() {
    if [[ "${mounted:-0}" -eq 1 ]]; then hdiutil detach -quiet "$mount_point" || true; fi
}
trap 'cleanup_mount; rm -rf -- "$work"' EXIT
app="$mount_point/ConMan.app"
[[ -d "$app" ]] || { echo "DMG does not contain ConMan.app" >&2; exit 1; }
bundle_version=$(plutil -extract CFBundleVersion raw "$app/Contents/Info.plist")
short_version=$(plutil -extract CFBundleShortVersionString raw "$app/Contents/Info.plist")
expected_short=$(printf '%s\n' "$version" | sed -nE 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
[[ "$bundle_version" == "$revision" ]] || { echo "DMG CFBundleVersion $bundle_version != revision $revision" >&2; exit 1; }
[[ "$short_version" == "$expected_short" ]] || { echo "DMG short version $short_version != $expected_short" >&2; exit 1; }
[[ $(plutil -extract CFBundleIdentifier raw "$app/Contents/Info.plist") == "com.marcos0ft.conman" ]] || {
    echo "DMG has the wrong ConMan bundle identifier" >&2
    exit 1
}
mounted=0
hdiutil detach -quiet "$mount_point"

download_prefix="https://github.com/MarcoS0ft/ConMan/releases/download/${release_tag}/"
notes_prefix="https://github.com/MarcoS0ft/ConMan/releases/tag/${release_tag}/"
link="https://github.com/MarcoS0ft/ConMan/releases/tag/${release_tag}"

# Sparkle 2.9.4 reads the private Ed25519 key from stdin when --ed-key-file is
# '-'. The pipe intentionally keeps the private key out of temporary files.
printf '%s' "$CONMAN_SPARKLE_ED25519_PRIVATE_KEY" \
    | "$tool" --ed-key-file - \
        --download-url-prefix "$download_prefix" \
        --release-notes-url-prefix "$notes_prefix" \
        --full-release-notes-url "$link" \
        --link "$link" \
        --channel "$channel" \
        --disable-signing-warning \
        -o "$appcast" "$archives"

xmllint --nonet --noout "$appcast"
[[ $(stat -f '%z' "$dmg") -gt 0 ]] || { echo "DMG is empty" >&2; exit 1; }
grep -Fq "<sparkle:version>$revision</sparkle:version>" "$appcast" || { echo "appcast revision does not match the DMG" >&2; exit 1; }
grep -Fq "<sparkle:shortVersionString>$expected_short</sparkle:shortVersionString>" "$appcast" || {
    echo "appcast short version does not match the DMG" >&2
    exit 1
}
grep -Fq "<sparkle:channel>$channel</sparkle:channel>" "$appcast" || { echo "appcast channel is missing" >&2; exit 1; }
grep -Fq "sparkle:edSignature=\"" "$appcast" || { echo "appcast enclosure is unsigned" >&2; exit 1; }
grep -Eq 'length="[1-9][0-9]*"' "$appcast" || { echo "appcast enclosure length is missing" >&2; exit 1; }
grep -Fq "<sparkle:fullReleaseNotesLink>$link</sparkle:fullReleaseNotesLink>" "$appcast" || { echo "appcast release notes URL is missing" >&2; exit 1; }
grep -Fq "$download_prefix$dmg_name" "$appcast" || { echo "appcast points at an unexpected enclosure" >&2; exit 1; }
if grep -Eq 'file://|/tmp/|/private/' "$appcast"; then
    echo "appcast contains a local enclosure path" >&2
    exit 1
fi

printf 'APPCAST=%s\nCHANNEL=%s\nRELEASE_TAG=%s\nVERSION=%s\nREVISION=%s\n' \
    "$appcast" "$channel" "$release_tag" "$version" "$revision"
