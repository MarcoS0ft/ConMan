#!/usr/bin/env bash
# Build the tiny Swift/AppKit Sparkle bridge used by cm-update-macos.
#
# The bridge is compiled separately because Sparkle is a macOS framework. The
# Rust adapter links this dylib with an @rpath pointing at the final app's
# Contents/Frameworks directory. The package builder signs it before signing
# the outer ConMan.app.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
sparkle_dir="${CONMAN_SPARKLE_DIR:-}"
output_dir="$repo_root/dist/macos-bridge"
deployment_target="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
swift_target="${CONMAN_SWIFT_TARGET:-}"

usage() {
    cat <<'EOF'
Usage: build-sparkle-bridge.sh --sparkle-dir SPARKLE.framework \
       [--output-dir DIR] [--target TARGET]

TARGET defaults to the host architecture. The production universal build must
invoke this once per architecture and lipo the resulting dylibs before app
packaging.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sparkle-dir) sparkle_dir=$2; shift 2 ;;
        --output-dir) output_dir=$2; shift 2 ;;
        --target) swift_target=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$sparkle_dir" ]] || { echo "--sparkle-dir is required" >&2; exit 2; }
[[ -x "$sparkle_dir/Sparkle" ]] || { echo "Sparkle framework is incomplete: $sparkle_dir" >&2; exit 1; }
sparkle_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$sparkle_dir/Resources/Info.plist" 2>/dev/null || true)
[[ "$sparkle_version" == "2.9.4" ]] || {
    echo "Sparkle framework must be version 2.9.4, got ${sparkle_version:-unknown}" >&2
    exit 1
}
command -v swiftc >/dev/null || { echo "swiftc is required" >&2; exit 1; }
command -v xcrun >/dev/null || { echo "xcrun is required" >&2; exit 1; }

if [[ -z "$swift_target" ]]; then
    host_arch=$(uname -m)
    case "$host_arch" in
        arm64|aarch64) host_arch=arm64 ;;
        x86_64) ;;
        *) echo "Unsupported macOS bridge architecture: $host_arch" >&2; exit 1 ;;
    esac
    swift_target="${host_arch}-apple-macos${deployment_target}"
fi

mkdir -p "$output_dir"
bridge="$output_dir/ConManSparkleBridge.dylib"
args=(
    -parse-as-library
    -module-name ConManSparkleBridge
    -emit-library
    -O
    -framework Sparkle
    -F "$(dirname "$sparkle_dir")"
    -Xlinker -rpath -Xlinker '@loader_path/../Frameworks'
    -Xlinker -install_name -Xlinker '@rpath/ConManSparkleBridge.dylib'
    -target "$swift_target"
    -o "$bridge"
    "$repo_root/packaging/macos/updater/ConManSparkleBridge.swift"
)
swiftc "${args[@]}"

otool -L "$bridge" | grep -Fq 'Sparkle.framework/Versions/B/Sparkle' || {
    echo "Sparkle bridge does not link the pinned Sparkle framework" >&2
    exit 1
}

printf 'BRIDGE=%s\nDEPLOYMENT_TARGET=%s\n' "$bridge" "$deployment_target"
