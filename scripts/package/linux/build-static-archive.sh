#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "${SCRIPT_DIR}/common.sh"

REPO_ROOT=$(linux_package_root)
BINARY_DIR=${1:-"${REPO_ROOT}/target/x86_64-unknown-linux-musl/release"}
OUTPUT_DIR=${2:-"${REPO_ROOT}/dist/packages"}
ARCH=$(normalize_arch "${ARCH:-$(uname -m)}")

need_command file
need_command readelf
need_command ldd
need_command sha256sum
require_release_binaries "$BINARY_DIR"
assert_fully_static_elf "${BINARY_DIR}/conman"
assert_fully_static_elf "${BINARY_DIR}/conmanctl"
VERSION=$(binary_version "$BINARY_DIR")
NAME="conman-$(artifact_version "$VERSION")-linux-${ARCH}-static"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/conman-static.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
ROOT="${WORK}/${NAME}"
mkdir -p "${ROOT}/bin"
install -m0755 "${BINARY_DIR}/conman" "${ROOT}/bin/conman"
install -m0755 "${BINARY_DIR}/conmanctl" "${ROOT}/bin/conmanctl"
install -Dm0644 "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.desktop" \
    "${ROOT}/share/applications/com.marcos0ft.conman.desktop"
install -Dm0644 "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.metainfo.xml" \
    "${ROOT}/share/metainfo/com.marcos0ft.conman.appdata.xml"
install -Dm0644 "${REPO_ROOT}/resources/ConMan_128.png" \
    "${ROOT}/share/icons/hicolor/128x128/apps/com.marcos0ft.conman.png"
install_distribution_notices "$REPO_ROOT" "${ROOT}/share/doc/conman"
install -m0755 "${SCRIPT_DIR}/static-install.sh" "${ROOT}/install.sh"
printf '# ConMan %s static Linux build\n\n' "$VERSION" >"${ROOT}/README.md"
cat >>"${ROOT}/README.md" <<'EOF'
Both `bin/conman` and `bin/conmanctl` are fully static musl ELF
executables: packaging rejected them unless they had no ELF interpreter and no
DT_NEEDED entries. A graphical program still requires a host display server,
graphics/input services, and appropriate device drivers.

Run in place or execute `./install.sh`. It installs to `/usr/local` as root and
`~/.local` otherwise; set `PREFIX` to override the binary prefix.
EOF
(cd "$ROOT" && sha256sum bin/conman bin/conmanctl > SHA256SUMS)

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
ARTIFACT="${OUTPUT_DIR}/${NAME}.tar.gz"
tar -C "$WORK" -czf "$ARTIFACT" "$NAME"
write_sha256 "$ARTIFACT"

# Re-extract and prove the published payload, not merely its sources.
VERIFY="${WORK}/verify"
mkdir -p "$VERIFY"
tar -C "$VERIFY" -xzf "$ARTIFACT"
(cd "${VERIFY}/${NAME}" && sha256sum -c SHA256SUMS)
assert_fully_static_elf "${VERIFY}/${NAME}/bin/conman"
assert_fully_static_elf "${VERIFY}/${NAME}/bin/conmanctl"
printf 'Static archive: %s\n' "$ARTIFACT"
