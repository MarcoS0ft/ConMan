#!/usr/bin/env bash
# Fetch the exact Sparkle distribution used by ConMan's macOS adapter.
#
# Sparkle is a signed nested framework with XPC services and updater helpers;
# do not replace this with a framework-only download or a floating tag. The
# archive is verified before it is extracted, and the extracted tree is
# copied with ditto so framework symlinks are preserved.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
sparkle_version=2.9.4
sparkle_url="https://github.com/sparkle-project/Sparkle/releases/download/${sparkle_version}/Sparkle-${sparkle_version}.tar.xz"
sparkle_sha256="ce89daf967db1e1893ed3ebd67575ed82d3902563e3191ca92aaec9164fbdef9"
output_dir="$repo_root/dist/macos/.sparkle"

usage() {
    cat <<'EOF'
Usage: fetch-sparkle.sh [--output-dir DIR]

Downloads the pinned Sparkle 2.9.4 distribution, verifies its SHA-256, and
prints SPARKLE_DIR=<path> for use by the macOS package builder.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) output_dir=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for tool in curl shasum tar ditto; do
    command -v "$tool" >/dev/null || {
        echo "Required macOS tool not found: $tool" >&2
        exit 1
    }
done

mkdir -p "$output_dir"
archive="$output_dir/Sparkle-${sparkle_version}.tar.xz"
framework="$output_dir/Sparkle.framework"

if [[ -f "$archive" ]]; then
    actual=$(shasum -a 256 "$archive" | awk '{print $1}')
    [[ "$actual" == "$sparkle_sha256" ]] || {
        echo "Cached Sparkle archive checksum mismatch: $actual" >&2
        exit 1
    }
else
    curl --fail --location --retry 3 --retry-delay 2 --silent --show-error \
        "$sparkle_url" --output "$archive"
    actual=$(shasum -a 256 "$archive" | awk '{print $1}')
    [[ "$actual" == "$sparkle_sha256" ]] || {
        echo "Sparkle ${sparkle_version} checksum mismatch: $actual" >&2
        exit 1
    }
fi

if [[ ! -x "$framework/Sparkle" || ! -d "$framework/XPCServices" || ! -d "$framework/Updater.app" || ! -x "$output_dir/bin/generate_appcast" || ! -x "$output_dir/bin/sign_update" ]]; then
    extract_dir=$(mktemp -d "${TMPDIR:-/tmp}/conman-sparkle.XXXXXX")
    trap 'rm -rf -- "$extract_dir"' EXIT
    tar -xJf "$archive" -C "$extract_dir"
    [[ -x "$extract_dir/Sparkle.framework/Sparkle" ]] || {
        echo "Sparkle archive did not contain its framework" >&2
        exit 1
    }
    ditto "$extract_dir/Sparkle.framework" "$framework"
    [[ -x "$extract_dir/bin/generate_appcast" && -x "$extract_dir/bin/sign_update" ]] || {
        echo "Sparkle archive did not contain its signing tools" >&2
        exit 1
    }
    ditto "$extract_dir/bin" "$output_dir/bin"
fi

framework_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$framework/Resources/Info.plist" 2>/dev/null || true)
[[ "$framework_version" == "$sparkle_version" ]] || {
    echo "Sparkle framework version mismatch: expected $sparkle_version, got ${framework_version:-unknown}" >&2
    exit 1
}

printf 'SPARKLE_VERSION=%s\nSPARKLE_URL=%s\nSPARKLE_SHA256=%s\nSPARKLE_DIR=%s\n' \
    "$sparkle_version" "$sparkle_url" "$sparkle_sha256" "$framework"
