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
CARGO_CACHE_DIR=${CARGO_CACHE_DIR:-"${REPO_ROOT}/.cache/cargo-linux-static"}
mkdir -p "$CARGO_CACHE_DIR"

# Alpine's native Rust target is musl. Static variants of every C library used
# directly by ConMan are installed; the final archive builder independently
# rejects any residual interpreter or DT_NEEDED entry.
"$ENGINE" run --rm \
    -e CARGO_HOME=/cargo \
    -e CARGO_TARGET_DIR=/work/target/static-musl \
    -e LIBGHOSTTY_VT_SYS_CPU="${LIBGHOSTTY_VT_SYS_CPU:-x86_64_v2}" \
    -v "${REPO_ROOT}:/work:Z" \
    -v "${CARGO_CACHE_DIR}:/cargo:Z" \
    -v "${OUTPUT_DIR}:/output:Z" \
    -w /work \
    docker.io/library/rust@sha256:8b5aee3b8fb41756d8447a47f96edc87a21f1e0c2b5ad2f3059542637d6c9b93 \
    sh -euxc '
        apk add --no-cache \
          bash binutils build-base bzip2-dev bzip2-static ca-certificates curl expat-dev expat-static \
          file fontconfig-dev fontconfig-static freetype-dev freetype-static git \
          libpng-dev libpng-static libxkbcommon-dev libxkbcommon-static linux-headers \
          musl-dev perl pkgconf python3 tar xz xz-dev xz-static \
          brotli-dev brotli-static zlib-dev zlib-static
        eval "$(scripts/bootstrap-zig.sh --export)"
        export PKG_CONFIG_ALL_STATIC=1
        cargo build --locked --release -p conman -p conmanctl
        scripts/package/linux/build-static-archive.sh \
          /work/target/static-musl/release /output
    '

printf 'Static Linux artifacts are in %s\n' "$OUTPUT_DIR"
