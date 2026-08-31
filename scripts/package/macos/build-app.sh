#!/usr/bin/env bash
# Assemble release binaries into a conventional ConMan.app bundle.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
target_dir="$repo_root/target/release"
output_dir="$repo_root/dist/macos"
version=""
identity=""
app_profile=""
cli_profile=""

usage() {
    cat <<'EOF'
Usage: build-app.sh [--target-dir DIR] [--output-dir DIR] [--version VERSION]
                    [--sign-identity IDENTITY]
                    [--app-provisioning-profile FILE]
                    [--cli-provisioning-profile FILE]

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
        --app-provisioning-profile) app_profile=$2; shift 2 ;;
        --cli-provisioning-profile) cli_profile=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

profile_count=0
[[ -n "$app_profile" ]] && profile_count=$((profile_count + 1))
[[ -n "$cli_profile" ]] && profile_count=$((profile_count + 1))
if [[ "$profile_count" -ne 0 && "$profile_count" -ne 2 ]]; then
    echo "Both GUI and conmanctl provisioning profiles are required together" >&2
    exit 2
fi
if [[ -n "$identity" && "$identity" != "-" && "$profile_count" -ne 2 ]]; then
    echo "Developer ID signing requires GUI and conmanctl provisioning profiles" >&2
    exit 2
fi
if [[ "$profile_count" -eq 2 ]]; then
    [[ -f "$app_profile" ]] || { echo "GUI provisioning profile not found: $app_profile" >&2; exit 1; }
    [[ -f "$cli_profile" ]] || { echo "conmanctl provisioning profile not found: $cli_profile" >&2; exit 1; }

    command -v security >/dev/null || {
        echo "security is required to validate provisioning profiles" >&2
        exit 1
    }
    validate_profile() {
        local profile=$1
        local expected_app_id=$2
        local decoded
        decoded=$(mktemp "${TMPDIR:-/tmp}/conman-profile.XXXXXX")
        security cms -D -i "$profile" > "$decoded"
        local app_id
        app_id=$(plutil -extract 'Entitlements.com\.apple\.application-identifier' raw "$decoded")
        if [[ "$app_id" != "$expected_app_id" ]]; then
            rm -f "$decoded"
            echo "Provisioning profile authorizes $app_id, expected $expected_app_id" >&2
            exit 1
        fi
        local groups
        groups=$(plutil -extract Entitlements.keychain-access-groups.0 raw "$decoded")
        rm -f "$decoded"
        case "$groups" in
            *"2NZRF4HQT7.com.marcos0ft.conman.shared"*|*"2NZRF4HQT7.*"*) ;;
            *) echo "Provisioning profile does not authorize ConMan's Keychain Access Group" >&2; exit 1 ;;
        esac
    }
    validate_profile "$app_profile" "2NZRF4HQT7.com.marcos0ft.conman"
    validate_profile "$cli_profile" "2NZRF4HQT7.com.marcos0ft.conman.conmanctl"
fi

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
cli_app="$app/Contents/Helpers/conmanctl.app"
cli_executable="$cli_app/Contents/MacOS/conmanctl"
mkdir -p "$app/Contents/MacOS" "$cli_app/Contents/MacOS" \
    "$app/Contents/Resources/Licenses"
install -m 0755 "$conman" "$app/Contents/MacOS/conman"
install -m 0755 "$conmanctl" "$cli_executable"
install -m 0644 "$repo_root/packaging/macos/Info.plist" "$app/Contents/Info.plist"
install -m 0644 "$repo_root/packaging/macos/conmanctl-Info.plist" "$cli_app/Contents/Info.plist"
for license in \
    "$repo_root/LICENSE-MIT" \
    "$repo_root/LICENSE-APACHE" \
    "$repo_root/crates/cm-ui/assets/fonts/NOTICE.md" \
    "$repo_root/crates/cm-ui/assets/fonts/JetBrainsMono-OFL.txt" \
    "$repo_root/crates/cm-ui/assets/fonts/SymbolsNerdFont-LICENSE-MIT.txt"
do
    install -m 0644 "$license" "$app/Contents/Resources/Licenses/$(basename "$license")"
done
plutil -replace CFBundleShortVersionString -string "$short_version" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$build_version" "$app/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$short_version" "$cli_app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$build_version" "$cli_app/Contents/Info.plist"

if [[ "$profile_count" -eq 2 ]]; then
    install -m 0644 "$app_profile" "$app/Contents/embedded.provisionprofile"
    install -m 0644 "$cli_profile" "$cli_app/Contents/embedded.provisionprofile"
fi

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
    if [[ "$identity" == "-" ]]; then
        # Ad-hoc builds intentionally have no restricted Keychain entitlement.
        # Saved credentials are unavailable until the build carries profiles
        # issued by ConMan's Apple Developer team.
        codesign "${sign_args[@]}" "$cli_app"
        codesign "${sign_args[@]}" "$app/Contents/MacOS/conman"
        codesign "${sign_args[@]}" "$app"
    else
        codesign "${sign_args[@]}" \
            --entitlements "$repo_root/packaging/macos/conmanctl.entitlements" "$cli_app"
        codesign "${sign_args[@]}" "$app/Contents/MacOS/conman"
        codesign "${sign_args[@]}" \
            --entitlements "$repo_root/packaging/macos/ConMan.entitlements" "$app"
    fi
    codesign --verify --deep --strict --verbose=2 "$app"
fi

printf 'APP=%s\nVERSION=%s\n' "$app" "$version"
