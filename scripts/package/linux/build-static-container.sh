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
    else die "podman or docker is required for the reproducible musl build"
    fi
fi
need_command "$ENGINE"
mkdir -p "$OUTPUT_DIR" "${REPO_ROOT}/target"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
CACHE_ROOT=$(linux_package_cache_root)
CONTAINERFILE="${REPO_ROOT}/packaging/linux/Containerfile.musl"
BUILDER_IMAGE=$(ensure_linux_builder_image "$ENGINE" "$CONTAINERFILE" musl)
BUILDER_KEY=${BUILDER_IMAGE##*:}
CARGO_CACHE_DIR=${CARGO_CACHE_DIR:-"${CACHE_ROOT}/cargo"}
TARGET_CACHE_DIR=${TARGET_CACHE_DIR:-"${CACHE_ROOT}/targets/musl-${BUILDER_KEY}"}
mkdir -p "$CARGO_CACHE_DIR" "$TARGET_CACHE_DIR"

# Alpine's native Rust target is musl. Static variants of every C library used
# directly by ConMan are installed; the final archive builder independently
# rejects any residual interpreter or DT_NEEDED entry.
"$ENGINE" run --rm \
    -e CARGO_HOME=/cargo \
    -e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    -e CARGO_PROFILE_RELEASE_LTO=false \
    -e CARGO_TARGET_DIR=/work/target/static-musl \
    -e EXPECTED_VERSION="${EXPECTED_VERSION:-}" \
    -e LIBGHOSTTY_VT_SYS_CPU="${LIBGHOSTTY_VT_SYS_CPU:-x86_64_v2}" \
    -v "${REPO_ROOT}:/work:Z" \
    -v "${CARGO_CACHE_DIR}:/cargo:Z" \
    -v "${TARGET_CACHE_DIR}:/work/target/static-musl:Z" \
    -v "${OUTPUT_DIR}:/output:Z" \
    -w /work \
    "$BUILDER_IMAGE" \
    sh -euxc '
        export PKG_CONFIG_ALL_STATIC=1
        cargo build --locked --release -p conman -p conmanctl
        scripts/package/linux/build-static-archive.sh \
          /work/target/static-musl/release /output
    '

printf 'Static Linux artifacts are in %s\n' "$OUTPUT_DIR"
