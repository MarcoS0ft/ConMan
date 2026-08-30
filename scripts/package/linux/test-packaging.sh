#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "${SCRIPT_DIR}/common.sh"
REPO_ROOT=$(linux_package_root)

need_command desktop-file-validate
need_command readelf
desktop-file-validate "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.desktop"
grep -q '<id>com.marcos0ft.conman</id>' \
    "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.metainfo.xml"

[ "$(normalize_arch amd64)" = x86_64 ]
[ "$(deb_arch aarch64)" = arm64 ]
[ "$(artifact_version '0.1.0-dev.2+gabc')" = '0.1.0-dev.2-gabc' ]
[ "$(deb_version '0.1.0-dev.2+gabc')" = '0.1.0~dev.2+gabc' ]
[ "$(rpm_version '0.1.0-dev.2+gabc')" = '0.1.0~dev.2.gabc' ]
EXPECTED_VERSION=0.1.0 require_expected_version 0.1.0
if (EXPECTED_VERSION=0.1.0 require_expected_version 0.1.1) >/dev/null 2>&1; then
    die "expected-version validation accepted a mismatched binary"
fi
if command -v rpmdev-vercmp >/dev/null 2>&1; then
    if rpmdev-vercmp '0.1.0~dev.1-1' '0.1.0-1' >/dev/null; then rpm_cmp=0; else rpm_cmp=$?; fi
    [ "$rpm_cmp" -eq 12 ] || die "RPM prerelease does not sort before stable"
elif command -v rpm >/dev/null 2>&1; then
    [ "$(rpm --eval '%{lua: print(rpm.vercmp("0.1.0~dev.1", "0.1.0"))}')" = -1 ] || \
        die "RPM prerelease does not sort before stable"
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/conman-package-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
cp /bin/true "${WORK}/dynamic"
if (assert_fully_static_elf "${WORK}/dynamic") >/dev/null 2>&1; then
    die "static validation accepted a dynamically linked executable"
fi
printf 'tampered' >"${WORK}/tool"
if (verify_sha256 "${WORK}/tool" '0000000000000000000000000000000000000000000000000000000000000000') \
    >/dev/null 2>&1; then
    die "checksum validation accepted incorrect bytes"
fi

# Exercise AppRun routing without requiring AppImage/FUSE.
mkdir -p "${WORK}/AppDir/usr/bin" "${WORK}/home"
cp "${SCRIPT_DIR}/AppRun" "${WORK}/AppDir/AppRun"
cat >"${WORK}/AppDir/usr/bin/conmanctl" <<'EOF'
#!/bin/sh
printf 'ctl:%s\n' "$*"
EOF
cat >"${WORK}/AppDir/usr/bin/conman" <<'EOF'
#!/bin/sh
printf 'gui:%s\n' "$*"
EOF
chmod 0755 "${WORK}/AppDir/AppRun" "${WORK}/AppDir/usr/bin/conman" "${WORK}/AppDir/usr/bin/conmanctl"
[ "$("${WORK}/AppDir/AppRun" --conmanctl ping)" = 'ctl:ping' ]
[ "$("${WORK}/AppDir/AppRun" --example)" = 'gui:--example' ]
HOME="${WORK}/home" "${WORK}/AppDir/AppRun" --install-cli >/dev/null
[ "$("${WORK}/home/.local/bin/conmanctl" test)" = 'ctl:test' ]
HOME="${WORK}/home" "${WORK}/AppDir/AppRun" --uninstall-cli >/dev/null
[ ! -e "${WORK}/home/.local/bin/conmanctl" ]

printf 'Linux packaging contract tests passed.\n'
