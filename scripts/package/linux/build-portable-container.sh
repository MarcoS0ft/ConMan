#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "${SCRIPT_DIR}/common.sh"

REPO_ROOT=$(linux_package_root)
OUTPUT_DIR=${1:-"${REPO_ROOT}/dist/packages"}
ENGINE=${ENGINE:-}
if [ -z "$ENGINE" ]; then
    if command -v podman >/dev/null 2>&1; then ENGINE=podman
    elif command -v docker >/dev/null 2>&1; then ENGINE=docker
    else die "podman or docker is required for the baseline Linux build"
    fi
fi
need_command "$ENGINE"
mkdir -p "$OUTPUT_DIR" "${REPO_ROOT}/target"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
CACHE_ROOT=$(linux_package_cache_root)
CONTAINERFILE="${REPO_ROOT}/packaging/linux/Containerfile.bookworm"
BUILDER_IMAGE=$(ensure_linux_builder_image "$ENGINE" "$CONTAINERFILE" bookworm)
BUILDER_KEY=${BUILDER_IMAGE##*:}
CARGO_CACHE_DIR=${CARGO_CACHE_DIR:-"${CACHE_ROOT}/cargo"}
TARGET_CACHE_DIR=${TARGET_CACHE_DIR:-"${CACHE_ROOT}/targets/bookworm-${BUILDER_KEY}"}
TOOLS_CACHE_DIR=${TOOLS_CACHE_DIR:-"${CACHE_ROOT}/tools"}
mkdir -p "$CARGO_CACHE_DIR" "$TARGET_CACHE_DIR" "$TOOLS_CACHE_DIR"

# Debian 12 provides a conservative glibc baseline. The image is digest-pinned;
# artifacts are built and dependency-scanned inside the same distribution.
"$ENGINE" run --rm \
    -e CARGO_HOME=/cargo \
    -e CARGO_TARGET_DIR=/work/target/package-bookworm \
    -e APPIMAGE_EXTRACT_AND_RUN=1 \
    -e EXPECTED_VERSION="${EXPECTED_VERSION:-}" \
    -e LIBGHOSTTY_VT_SYS_CPU="${LIBGHOSTTY_VT_SYS_CPU:-x86_64_v2}" \
    -e TOOLS_DIR=/tools-cache/appimage-tools \
    -v "${REPO_ROOT}:/work:Z" \
    -v "${CARGO_CACHE_DIR}:/cargo:Z" \
    -v "${TARGET_CACHE_DIR}:/work/target/package-bookworm:Z" \
    -v "${TOOLS_CACHE_DIR}:/tools-cache:Z" \
    -v "${OUTPUT_DIR}:/output:Z" \
    -w /work \
    "$BUILDER_IMAGE" \
    bash -euxo pipefail -c '
        cargo build --locked --release -p conman -p conmanctl
        prepare_args=(
          --target-dir /work/target/package-bookworm/release
          --stage-dir /work/dist/linux-stage
          --platform linux-x86_64
          --upx-cache /tools-cache/upx
        )
        if [ -n "$EXPECTED_VERSION" ]; then
          prepare_args+=(--expected-version "$EXPECTED_VERSION")
        fi
        python3 scripts/dist/prepare_release.py "${prepare_args[@]}"
        . scripts/package/linux/common.sh
        install_distribution_notices /work /work/dist/linux-stage/licenses
        PACKAGE_DEPENDENCY_BINARY_DIR=/work/target/package-bookworm/release \
          scripts/package/linux/build-deb.sh /work/dist/linux-stage /output
        APPIMAGE_DEPLOY_BINARY_DIR=/work/target/package-bookworm/release \
          scripts/package/linux/build-appimage.sh /work/dist/linux-stage /output
        python3 scripts/dist/package_release.py \
          --stage-dir /work/dist/linux-stage --output-dir /output
    '

scripts/package/linux/build-rpm.sh "${REPO_ROOT}/dist/linux-stage" "$OUTPUT_DIR"

printf 'Finalized Linux DEB, RPM, AppImage, and tar artifacts are in %s\n' "$OUTPUT_DIR"
