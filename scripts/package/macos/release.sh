#!/usr/bin/env bash
# Build a macOS app and DMG, optionally signing and notarizing a distribution.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd "$script_dir/../../.." && pwd -P)
target_dir="$repo_root/target/release"
output_dir="$repo_root/dist/macos"
version=""
identity=""
app_profile=""
cli_profile=""
notary_key=""
notary_key_id=""
notary_issuer=""

usage() {
    cat <<'EOF'
Usage: release.sh [--target-dir DIR] [--output-dir DIR] [--version VERSION]
                  [--sign-identity IDENTITY]
                  [--app-provisioning-profile FILE]
                  [--cli-provisioning-profile FILE]
                  [--notary-key FILE --notary-key-id ID --notary-issuer UUID]

Without signing arguments this creates an unsigned local-validation DMG. An
official release supplies a Developer ID Application identity and all three
App Store Connect notary arguments. Credentials are paths/values supplied by
the caller and are never stored in the repository.
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
        --notary-key) notary_key=$2; shift 2 ;;
        --notary-key-id) notary_key_id=$2; shift 2 ;;
        --notary-issuer) notary_issuer=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

notary_count=0
[[ -n "$notary_key" ]] && notary_count=$((notary_count + 1))
[[ -n "$notary_key_id" ]] && notary_count=$((notary_count + 1))
[[ -n "$notary_issuer" ]] && notary_count=$((notary_count + 1))
if [[ "$notary_count" -ne 0 && "$notary_count" -ne 3 ]]; then
    echo "Notarization requires --notary-key, --notary-key-id, and --notary-issuer together" >&2
    exit 2
fi
if [[ "$notary_count" -eq 3 && -z "$identity" ]]; then
    echo "Notarization requires --sign-identity" >&2
    exit 2
fi

app_args=(--target-dir "$target_dir" --output-dir "$output_dir")
[[ -n "$version" ]] && app_args+=(--version "$version")
[[ -n "$identity" ]] && app_args+=(--sign-identity "$identity")
[[ -n "$app_profile" ]] && app_args+=(--app-provisioning-profile "$app_profile")
[[ -n "$cli_profile" ]] && app_args+=(--cli-provisioning-profile "$cli_profile")
app_result=$("$script_dir/build-app.sh" "${app_args[@]}")
printf '%s\n' "$app_result"
app=$(printf '%s\n' "$app_result" | sed -n 's/^APP=//p')
version=$(printf '%s\n' "$app_result" | sed -n 's/^VERSION=//p')
[[ -d "$app" && -n "$version" ]] || { echo "build-app.sh returned invalid metadata" >&2; exit 1; }

notarize() {
    xcrun notarytool submit "$1" --key "$notary_key" --key-id "$notary_key_id" \
        --issuer "$notary_issuer" --wait --timeout 30m
}

dmg_result=$("$script_dir/build-dmg.sh" --app "$app" --output-dir "$output_dir" --version "$version")
printf '%s\n' "$dmg_result"
dmg=$(printf '%s\n' "$dmg_result" | sed -n 's/^DMG=//p')
[[ -f "$dmg" ]] || { echo "build-dmg.sh returned invalid metadata" >&2; exit 1; }

if [[ -n "$identity" ]]; then
    dmg_sign_args=(--force --sign "$identity")
    if [[ "$identity" == "-" ]]; then
        dmg_sign_args+=(--timestamp=none)
    else
        dmg_sign_args+=(--timestamp)
    fi
    codesign "${dmg_sign_args[@]}" "$dmg"
    codesign --verify --verbose=2 "$dmg"
fi

if [[ "$notary_count" -eq 3 ]]; then
    [[ -f "$notary_key" ]] || { echo "Notary API key not found: $notary_key" >&2; exit 1; }
    # The DMG is the product users download, so submit only this outermost
    # distribution container. Its signed app and nested executables are
    # inspected as part of the same notarization submission.
    notarize "$dmg"
    xcrun stapler staple "$dmg"
    xcrun stapler validate "$dmg"
fi

validate_args=(--app "$app" --dmg "$dmg" --version "$version")
[[ -n "$identity" ]] && validate_args+=(--require-signature)
[[ -n "$identity" && "$identity" != "-" ]] && validate_args+=(--require-keychain-sharing)
[[ "$notary_count" -eq 3 ]] && validate_args+=(--require-gatekeeper)
"$script_dir/validate.sh" "${validate_args[@]}"
(
    cd "$(dirname "$dmg")"
    shasum -a 256 "$(basename "$dmg")" > "$(basename "$dmg").sha256"
)
printf 'CHECKSUM=%s\n' "$dmg.sha256"
