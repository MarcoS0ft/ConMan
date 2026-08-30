#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "${SCRIPT_DIR}/common.sh"

REPO_ROOT=$(linux_package_root)
BINARY_DIR=${1:-"${REPO_ROOT}/target/release"}
OUTPUT_DIR=${2:-"${REPO_ROOT}/dist/packages"}
ARCH=$(normalize_arch "${ARCH:-$(uname -m)}")
DEB_ARCH=$(deb_arch "$ARCH")

need_command dpkg-deb
need_command file
need_command sha256sum
require_release_binaries "$BINARY_DIR"
require_finalized_stage "$BINARY_DIR"
VERSION=$(binary_version "$BINARY_DIR")
DEB_VERSION=$(deb_version "$VERSION")

WORK=$(mktemp -d "${TMPDIR:-/tmp}/conman-deb.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir -p "${WORK}/source"
cp "${BINARY_DIR}/conman" "${BINARY_DIR}/conmanctl" "${WORK}/source/"
ROOT="${WORK}/root"
install_desktop_payload "$ROOT" "$REPO_ROOT"

mkdir -p "${ROOT}/DEBIAN" "${ROOT}/usr/share/doc/conman"
cat >"${ROOT}/usr/share/doc/conman/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: ConMan
License: MIT or Apache-2.0
EOF

# dpkg-shlibdeps is authoritative when the package is built on Debian/Ubuntu.
# A caller may provide DEB_DEPENDS only for a controlled cross-package build.
if [ -n "${DEB_DEPENDS:-}" ]; then
    DEPENDS=$DEB_DEPENDS
else
    need_command dpkg-shlibdeps
    mkdir -p "${WORK}/debian"
    cat >"${WORK}/debian/control" <<EOF
Source: conman
Section: net
Priority: optional
Maintainer: ConMan maintainers
Standards-Version: 4.7.0

Package: conman
Architecture: ${DEB_ARCH}
Description: Connection Manager
EOF
    DEPENDENCY_BINARY_DIR=${PACKAGE_DEPENDENCY_BINARY_DIR:-$BINARY_DIR}
    require_release_binaries "$DEPENDENCY_BINARY_DIR"
    if ! DEPENDS=$(cd "$WORK" && dpkg-shlibdeps -O \
        "${DEPENDENCY_BINARY_DIR}/conman" "${DEPENDENCY_BINARY_DIR}/conmanctl" 2>/dev/null | sed -n 's/^shlibs:Depends=//p'); then
        die "dpkg-shlibdeps failed; build in Debian/Ubuntu or set DEB_DEPENDS explicitly"
    fi
    [ -n "$DEPENDS" ] || die "dpkg-shlibdeps could not derive Debian dependencies; build in Debian/Ubuntu or set DEB_DEPENDS explicitly"
fi

INSTALLED_SIZE=$(du -sk "$ROOT" | awk '{print $1}')
cat >"${ROOT}/DEBIAN/control" <<EOF
Package: conman
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: ConMan maintainers
Depends: ${DEPENDS}
Installed-Size: ${INSTALLED_SIZE}
Homepage: https://github.com/MarcoS0ft/conman
Description: Connection Manager
 Desktop connection manager for terminal, SSH, Telnet, and RDP sessions.
EOF

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
ARTIFACT="${OUTPUT_DIR}/conman-$(artifact_version "$VERSION")-linux-${ARCH}.deb"
dpkg-deb --root-owner-group --build "$ROOT" "$ARTIFACT"
dpkg-deb --info "$ARTIFACT" >/dev/null
dpkg-deb --contents "$ARTIFACT" >"${WORK}/contents.txt"
grep -q './usr/bin/conmanctl$' "${WORK}/contents.txt" || die "DEB is missing conmanctl"
mkdir -p "${WORK}/verify"
dpkg-deb --extract "$ARTIFACT" "${WORK}/verify"
"${WORK}/verify/usr/bin/conman" --version | grep -Fq "$VERSION" || die "packaged conman version smoke failed"
"${WORK}/verify/usr/bin/conmanctl" --version | grep -Fq "$VERSION" || die "packaged conmanctl version smoke failed"
write_sha256 "$ARTIFACT"
printf 'DEB: %s\n' "$ARTIFACT"
