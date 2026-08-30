#!/usr/bin/env bash
# Deterministically validate the app bundle and the mounted DMG contents.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
app=""
dmg=""
version=""
require_signature=0
require_gatekeeper=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app) app=$2; shift 2 ;;
        --dmg) dmg=$2; shift 2 ;;
        --version) version=$2; shift 2 ;;
        --require-signature) require_signature=1; shift ;;
        --require-gatekeeper) require_gatekeeper=1; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

[[ -d "$app" ]] || { echo "App bundle not found: $app" >&2; exit 1; }
[[ -f "$dmg" ]] || { echo "DMG not found: $dmg" >&2; exit 1; }
[[ -n "$version" ]] || { echo "--version is required" >&2; exit 2; }

plist="$app/Contents/Info.plist"
main="$app/Contents/MacOS/conman"
ctl="$app/Contents/Helpers/conmanctl"
icon="$app/Contents/Resources/ConMan.icns"
plutil -lint "$plist" >/dev/null
[[ $(plutil -extract CFBundleIdentifier raw "$plist") == "com.marcos0ft.conman" ]]
[[ $(plutil -extract CFBundleExecutable raw "$plist") == "conman" ]]
short_version=$(printf '%s\n' "$version" | sed -nE 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
[[ $(plutil -extract CFBundleShortVersionString raw "$plist") == "$short_version" ]]
for path in "$main" "$ctl"; do
    [[ -x "$path" ]] || { echo "Bundled executable is missing: $path" >&2; exit 1; }
    file "$path" | grep -q 'Mach-O' || { echo "Not a Mach-O executable: $path" >&2; exit 1; }
    "$path" --version | grep -Fq "$version" || { echo "Version check failed: $path" >&2; exit 1; }
done
[[ -s "$icon" ]] || { echo "App icon is missing" >&2; exit 1; }
license_dir="$app/Contents/Resources/Licenses"
[[ -d "$license_dir" ]] || { echo "App license directory is missing" >&2; exit 1; }
license_count=$(find "$license_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d '[:space:]')
[[ "$license_count" == 5 ]] || {
    echo "App must contain exactly five license files; found $license_count" >&2
    exit 1
}
for license in \
    "$repo_root/LICENSE-MIT" \
    "$repo_root/LICENSE-APACHE" \
    "$repo_root/crates/cm-ui/assets/fonts/NOTICE.md" \
    "$repo_root/crates/cm-ui/assets/fonts/JetBrainsMono-OFL.txt" \
    "$repo_root/crates/cm-ui/assets/fonts/SymbolsNerdFont-LICENSE-MIT.txt"
do
    bundled="$license_dir/$(basename "$license")"
    [[ -f "$bundled" ]] || { echo "Bundled license is missing: $bundled" >&2; exit 1; }
    cmp -s "$license" "$bundled" || { echo "Bundled license differs from source: $bundled" >&2; exit 1; }
done
if [[ "$require_signature" -eq 1 ]]; then
    codesign --verify --deep --strict --verbose=2 "$app"
fi
if [[ "$require_gatekeeper" -eq 1 ]]; then
    spctl --assess --type execute --verbose=2 "$app"
fi

mount_point=$(mktemp -d "${TMPDIR:-/tmp}/conman-mount.XXXXXX")
attached=0
cleanup() {
    if [[ "$attached" -eq 1 ]]; then
        hdiutil detach -quiet "$mount_point" || true
    fi
    rmdir "$mount_point" 2>/dev/null || true
}
trap cleanup EXIT
hdiutil attach -quiet -readonly -nobrowse -mountpoint "$mount_point" "$dmg"
attached=1
[[ -d "$mount_point/ConMan.app" ]]
[[ -L "$mount_point/Applications" && $(readlink "$mount_point/Applications") == "/Applications" ]]
[[ -x "$mount_point/Install conmanctl.command" ]]
[[ -f "$mount_point/README.txt" ]]
cmp -s "$app/Contents/MacOS/conman" "$mount_point/ConMan.app/Contents/MacOS/conman"
cmp -s "$app/Contents/Helpers/conmanctl" "$mount_point/ConMan.app/Contents/Helpers/conmanctl"
mounted_license_dir="$mount_point/ConMan.app/Contents/Resources/Licenses"
mounted_license_count=$(find "$mounted_license_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d '[:space:]')
[[ "$mounted_license_count" == 5 ]] || {
    echo "DMG app must contain exactly five license files; found $mounted_license_count" >&2
    exit 1
}
for license in "$license_dir"/*; do
    cmp -s "$license" \
        "$mounted_license_dir/$(basename "$license")" \
        || { echo "DMG license differs from app: $(basename "$license")" >&2; exit 1; }
done
"$script_dir/test-installer.sh"

echo "Validated ConMan.app and $(basename "$dmg") for version $version"
