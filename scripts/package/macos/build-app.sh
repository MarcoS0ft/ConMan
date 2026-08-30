#!/usr/bin/env bash
# Assemble release binaries into a conventional ConMan.app bundle.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
target_dir="$repo_root/target/release"
output_dir="$repo_root/dist/macos"
version=""
identity=""

usage() {
    cat <<'EOF'
Usage: build-app.sh [--target-dir DIR] [--output-dir DIR] [--version VERSION]
                    [--sign-identity IDENTITY]

IDENTITY may be '-' for an ad-hoc local signature. Official releases should use
a Developer ID Application identity available in the current keychain.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-dir) target_dir=$2; shift 2 ;;
        --output-dir) output_dir=$2; shift 2 ;;
        --version) version=$2; shift 2 ;;
        --sign-identity) identity=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for tool in iconutil plutil sips; do
    command -v "$tool" >/dev/null || {
        echo "Required macOS tool not found: $tool" >&2
        exit 1
    }
done

conman="$target_dir/conman"
conmanctl="$target_dir/conmanctl"
for executable in "$conman" "$conmanctl"; do
    [[ -x "$executable" ]] || {
        echo "Required release executable is missing: $executable" >&2
        exit 1
    }
done

reported=$($conmanctl --version)
reported_version=$(printf '%s\n' "$reported" \
    | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+[^[:space:]]*' \
    | head -1)
[[ -n "$reported_version" ]] || {
    echo "Could not determine a version from: $reported" >&2
    exit 1
}
if [[ -z "$version" ]]; then
    version=$reported_version
elif [[ "$reported_version" != "$version" ]]; then
    echo "Requested version $version does not match binary version $reported_version" >&2
    exit 1
fi

short_version=$(printf '%s\n' "$version" | sed -nE 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
[[ -n "$short_version" ]] || {
    echo "Version is not based on MAJOR.MINOR.PATCH: $version" >&2
    exit 1
}
build_version=$(printf '%s\n' "$version" | sed -nE 's/.*-dev\.([0-9]+).*/\1/p')
[[ -n "$build_version" ]] || build_version=1

mkdir -p "$output_dir"
app="$output_dir/ConMan.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Resources"
install -m 0755 "$conman" "$app/Contents/MacOS/conman"
install -m 0755 "$conmanctl" "$app/Contents/Helpers/conmanctl"
install -m 0644 "$repo_root/packaging/macos/Info.plist" "$app/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$short_version" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$build_version" "$app/Contents/Info.plist"

icon_work=$(mktemp -d "${TMPDIR:-/tmp}/conman-icon.XXXXXX")
trap 'rm -rf "$icon_work"' EXIT
iconset="$icon_work/ConMan.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$repo_root/resources/ConMan.png" \
        --out "$iconset/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$repo_root/resources/ConMan.png" \
        --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/ConMan.icns"

if [[ -n "$identity" ]]; then
    command -v codesign >/dev/null || {
        echo "codesign is required when --sign-identity is used" >&2
        exit 1
    }
    sign_args=(--force --sign "$identity")
    if [[ "$identity" == "-" ]]; then
        sign_args+=(--timestamp=none)
    else
        sign_args+=(--options runtime --timestamp)
    fi
    codesign "${sign_args[@]}" "$app/Contents/Helpers/conmanctl"
    codesign "${sign_args[@]}" "$app/Contents/MacOS/conman"
    codesign "${sign_args[@]}" \
        --entitlements "$repo_root/packaging/macos/ConMan.entitlements" "$app"
    codesign --verify --deep --strict --verbose=2 "$app"
fi

printf 'APP=%s\nVERSION=%s\n' "$app" "$version"
