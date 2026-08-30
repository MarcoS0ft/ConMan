#!/usr/bin/env bash
# Create a drag-to-Applications DMG containing ConMan and its CLI installer.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
app=""
output_dir="$repo_root/dist/macos"
version=""

usage() {
    echo "Usage: build-dmg.sh --app PATH --version VERSION [--output-dir DIR]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app) app=$2; shift 2 ;;
        --output-dir) output_dir=$2; shift 2 ;;
        --version) version=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -d "$app" ]] || { echo "ConMan.app not found: $app" >&2; exit 1; }
[[ -n "$version" ]] || { echo "--version is required" >&2; exit 2; }
command -v hdiutil >/dev/null || { echo "hdiutil is required" >&2; exit 1; }
command -v lipo >/dev/null || { echo "lipo is required" >&2; exit 1; }

main_arches=$(lipo -archs "$app/Contents/MacOS/conman")
ctl_arches=$(lipo -archs "$app/Contents/Helpers/conmanctl")
[[ "$main_arches" == "$ctl_arches" ]] || {
    echo "App executables have different architectures: conman=$main_arches conmanctl=$ctl_arches" >&2
    exit 1
}
case " $main_arches " in
    " arm64 ") platform="macos-arm64" ;;
    " x86_64 ") platform="macos-x86_64" ;;
    " arm64 x86_64 "|" x86_64 arm64 ") platform="macos-universal" ;;
    *) echo "Unsupported macOS architecture set: $main_arches" >&2; exit 1 ;;
esac

mkdir -p "$output_dir"
stage=$(mktemp -d "${TMPDIR:-/tmp}/conman-dmg.XXXXXX")
trap 'rm -rf "$stage"' EXIT
ditto "$app" "$stage/ConMan.app"
ln -s /Applications "$stage/Applications"
install -m 0755 "$repo_root/packaging/macos/Install conmanctl.command" \
    "$stage/Install conmanctl.command"
install -m 0644 "$repo_root/packaging/macos/README.txt" "$stage/README.txt"

safe_version=$(printf '%s' "$version" | sed 's/[^0-9A-Za-z._-]/-/g')
dmg="$output_dir/ConMan-${safe_version}-${platform}.dmg"
rm -f "$dmg"
hdiutil create -quiet -volname "ConMan $version" -srcfolder "$stage" \
    -format UDZO -ov "$dmg"
printf 'DMG=%s\n' "$dmg"
