#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "${SCRIPT_DIR}/common.sh"

REPO_ROOT=$(linux_package_root)
BINARY_DIR=${1:-"${REPO_ROOT}/target/release"}
OUTPUT_DIR=${2:-"${REPO_ROOT}/dist/packages"}
ARCH=$(normalize_arch "${ARCH:-$(uname -m)}")
[ "$ARCH" = x86_64 ] || die "automatic AppImage tooling is currently available only for x86_64"

need_command file
need_command curl
need_command sha256sum
require_release_binaries "$BINARY_DIR"
require_finalized_stage "$BINARY_DIR"
VERSION=$(binary_version "$BINARY_DIR")
DEPLOY_BINARY_DIR=${APPIMAGE_DEPLOY_BINARY_DIR:-$BINARY_DIR}
require_release_binaries "$DEPLOY_BINARY_DIR"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/conman-appimage.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
TOOLS_DIR=${TOOLS_DIR:-"${REPO_ROOT}/.cache/appimage-tools"}
mkdir -p "$TOOLS_DIR"

fetch_tool() {
    local env_value=$1 command_name=$2 asset=$3 repository=$4 expected_sha=$5 output
    if [ -n "$env_value" ]; then
        [ -x "$env_value" ] || die "$command_name is not executable: $env_value"
        printf '%s\n' "$env_value"
        return
    fi
    if command -v "$command_name" >/dev/null 2>&1; then
        command -v "$command_name"
        return
    fi
    output="${TOOLS_DIR}/${asset}"
    if [ -e "$output" ] && ! (verify_sha256 "$output" "$expected_sha") 2>/dev/null; then
        rm -f "$output"
    fi
    if [ ! -x "$output" ]; then
        curl -fL --retry 3 -o "$output" \
            "https://github.com/${repository}/releases/download/continuous/${asset}"
        verify_sha256 "$output" "$expected_sha"
        chmod 0755 "$output"
    fi
    verify_sha256 "$output" "$expected_sha"
    printf '%s\n' "$output"
}

# linuxdeploy build 367 / commit 07333c6e942c7d71782b66be924c5d867f9dfdfc
# and appimagetool build 295. Their upstream uses a mutable `continuous` tag,
# so bytes are pinned here; any upstream replacement fails closed until review.
LINUXDEPLOY_BIN=$(fetch_tool "${LINUXDEPLOY:-}" linuxdeploy linuxdeploy-x86_64.AppImage \
    linuxdeploy/linuxdeploy 421ca71d5c69ea97c6309276232990d43df1dcece0edfaa26bbf926ff96ed12e)
APPIMAGETOOL_BIN=$(fetch_tool "${APPIMAGETOOL:-}" appimagetool appimagetool-x86_64.AppImage \
    AppImage/appimagetool a6d71e2b6cd66f8e8d16c37ad164658985e0cf5fcaa950c90a482890cb9d13e0)
if [ -n "${APPIMAGE_RUNTIME:-}" ]; then
    RUNTIME_BIN=$APPIMAGE_RUNTIME
    [ -f "$RUNTIME_BIN" ] || die "AppImage runtime not found: $RUNTIME_BIN"
else
    RUNTIME_BIN="${TOOLS_DIR}/runtime-x86_64"
    RUNTIME_SHA=1cc49bcf1e2ccd593c379adb17c9f85a36d619088296504de95b1d06215aebbf
    if [ -e "$RUNTIME_BIN" ] && ! (verify_sha256 "$RUNTIME_BIN" "$RUNTIME_SHA") 2>/dev/null; then
        rm -f "$RUNTIME_BIN"
    fi
    if [ ! -f "$RUNTIME_BIN" ]; then
        curl -fL --retry 3 -o "$RUNTIME_BIN" \
            https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64
    fi
    verify_sha256 "$RUNTIME_BIN" "$RUNTIME_SHA"
fi
EXTRACT=()
if [ ! -e /dev/fuse ] || [ "${APPIMAGE_EXTRACT_AND_RUN:-0}" = 1 ]; then
    EXTRACT=(--appimage-extract-and-run)
    export APPIMAGE_EXTRACT_AND_RUN=1
fi

APPDIR="${WORK}/ConMan.AppDir"
mkdir -p "${APPDIR}/usr/bin"
install -m0755 "${DEPLOY_BINARY_DIR}/conman" "${APPDIR}/usr/bin/conman"
install -m0755 "${DEPLOY_BINARY_DIR}/conmanctl" "${APPDIR}/usr/bin/conmanctl"
install -m0755 "${SCRIPT_DIR}/AppRun" "${APPDIR}/AppRun"
install -Dm0644 "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.desktop" \
    "${APPDIR}/usr/share/applications/com.marcos0ft.conman.desktop"
install -Dm0644 "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.metainfo.xml" \
    "${APPDIR}/usr/share/metainfo/com.marcos0ft.conman.appdata.xml"
install -Dm0644 "${REPO_ROOT}/resources/ConMan_128.png" \
    "${APPDIR}/usr/share/icons/hicolor/128x128/apps/com.marcos0ft.conman.png"
install_distribution_notices "$REPO_ROOT" "${APPDIR}/usr/share/doc/conman"
ln -s usr/share/applications/com.marcos0ft.conman.desktop "${APPDIR}/com.marcos0ft.conman.desktop"
ln -s usr/share/icons/hicolor/128x128/apps/com.marcos0ft.conman.png "${APPDIR}/com.marcos0ft.conman.png"

"$LINUXDEPLOY_BIN" "${EXTRACT[@]}" --appdir "$APPDIR" \
    --executable "${APPDIR}/usr/bin/conman" \
    --executable "${APPDIR}/usr/bin/conmanctl" \
    --desktop-file "${APPDIR}/usr/share/applications/com.marcos0ft.conman.desktop" \
    --icon-file "${APPDIR}/usr/share/icons/hicolor/128x128/apps/com.marcos0ft.conman.png"

# linuxdeploy must inspect and patch ordinary ELF files. Replace them only
# after deployment with prepare_release.py's UPX-tested finalized copies;
# AppRun's LD_LIBRARY_PATH keeps the deployed runtime visible.
install -m0755 "${BINARY_DIR}/conman" "${APPDIR}/usr/bin/conman"
install -m0755 "${BINARY_DIR}/conmanctl" "${APPDIR}/usr/bin/conmanctl"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
ARTIFACT="${OUTPUT_DIR}/ConMan-$(artifact_version "$VERSION")-${ARCH}.AppImage"
ARCH="$ARCH" "$APPIMAGETOOL_BIN" "${EXTRACT[@]}" \
    --runtime-file "$RUNTIME_BIN" "$APPDIR" "$ARTIFACT"
chmod 0755 "$ARTIFACT"

# Validate the embedded CLI and the opt-in PATH installation without opening a GUI.
APPIMAGE_EXTRACT_AND_RUN=1 "$ARTIFACT" --conmanctl --version | grep -Fq "$VERSION" || \
    die "AppImage conmanctl version smoke failed"
APPIMAGE_EXTRACT_AND_RUN=1 "$ARTIFACT" --version | grep -Fq "$VERSION" || \
    die "AppImage conman version smoke failed"
TEST_HOME="${WORK}/home"
HOME="$TEST_HOME" APPIMAGE_EXTRACT_AND_RUN=1 "$ARTIFACT" --install-cli >/dev/null
"${TEST_HOME}/.local/bin/conmanctl" --version | grep -Fq "$VERSION" || \
    die "AppImage conmanctl installation smoke failed"
write_sha256 "$ARTIFACT"
printf 'AppImage: %s\n' "$ARTIFACT"
