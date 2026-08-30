#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "${SCRIPT_DIR}/common.sh"

REPO_ROOT=$(linux_package_root)
BINARY_DIR=${1:-"${REPO_ROOT}/target/release"}
OUTPUT_DIR=${2:-"${REPO_ROOT}/dist/packages"}
ARCH=$(normalize_arch "${ARCH:-$(uname -m)}")
RPM_ARCH=$(rpm_arch "$ARCH")

need_command rpmbuild
need_command file
need_command sha256sum
require_release_binaries "$BINARY_DIR"
require_finalized_stage "$BINARY_DIR"
VERSION=$(binary_version "$BINARY_DIR")
RPM_VERSION=$(rpm_version "$VERSION")

WORK=$(mktemp -d "${TMPDIR:-/tmp}/conman-rpm.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
TOP="${WORK}/rpmbuild"
mkdir -p "${TOP}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "${BINARY_DIR}/conman" "${TOP}/SOURCES/conman"
cp "${BINARY_DIR}/conmanctl" "${TOP}/SOURCES/conmanctl"
cp "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.desktop" "${TOP}/SOURCES/"
cp "${REPO_ROOT}/packaging/linux/com.marcos0ft.conman.metainfo.xml" "${TOP}/SOURCES/"
cp "${REPO_ROOT}/resources/ConMan_128.png" "${TOP}/SOURCES/com.marcos0ft.conman.png"
NOTICE_STAGE="${WORK}/notices"
install_distribution_notices "$REPO_ROOT" "$NOTICE_STAGE"
cp "${NOTICE_STAGE}"/* "${TOP}/SOURCES/"

cat >"${TOP}/SPECS/conman.spec" <<EOF
Name:           conman
Version:        ${RPM_VERSION}
Release:        1
Summary:        Connection Manager
License:        MIT OR Apache-2.0
URL:            https://github.com/MarcoS0ft/conman
BuildArch:      ${RPM_ARCH}
Requires:       glibc >= 2.35, fontconfig >= 2.12.6, libgcc
Source0:        conman
Source1:        conmanctl
Source2:        com.marcos0ft.conman.desktop
Source3:        com.marcos0ft.conman.metainfo.xml
Source4:        com.marcos0ft.conman.png
Source5:        LICENSE-MIT
Source6:        LICENSE-APACHE
Source7:        FONT-NOTICE.md
Source8:        JetBrainsMono-OFL.txt
Source9:        SymbolsNerdFont-LICENSE-MIT.txt

%description
Desktop connection manager for terminal, SSH, Telnet, and RDP sessions.

%prep

%build

%install
install -Dm0755 %{SOURCE0} %{buildroot}%{_bindir}/conman
install -Dm0755 %{SOURCE1} %{buildroot}%{_bindir}/conmanctl
install -Dm0644 %{SOURCE2} %{buildroot}%{_datadir}/applications/com.marcos0ft.conman.desktop
install -Dm0644 %{SOURCE3} %{buildroot}%{_metainfodir}/com.marcos0ft.conman.appdata.xml
install -Dm0644 %{SOURCE4} %{buildroot}%{_datadir}/icons/hicolor/128x128/apps/com.marcos0ft.conman.png
install -Dm0644 %{SOURCE5} %{buildroot}%{_licensedir}/conman/LICENSE-MIT
install -Dm0644 %{SOURCE6} %{buildroot}%{_licensedir}/conman/LICENSE-APACHE
install -Dm0644 %{SOURCE7} %{buildroot}%{_licensedir}/conman/FONT-NOTICE.md
install -Dm0644 %{SOURCE8} %{buildroot}%{_licensedir}/conman/JetBrainsMono-OFL.txt
install -Dm0644 %{SOURCE9} %{buildroot}%{_licensedir}/conman/SymbolsNerdFont-LICENSE-MIT.txt

%files
%{_bindir}/conman
%{_bindir}/conmanctl
%{_datadir}/applications/com.marcos0ft.conman.desktop
%{_metainfodir}/com.marcos0ft.conman.appdata.xml
%{_datadir}/icons/hicolor/128x128/apps/com.marcos0ft.conman.png
%license %{_licensedir}/conman/LICENSE-MIT
%license %{_licensedir}/conman/LICENSE-APACHE
%license %{_licensedir}/conman/FONT-NOTICE.md
%license %{_licensedir}/conman/JetBrainsMono-OFL.txt
%license %{_licensedir}/conman/SymbolsNerdFont-LICENSE-MIT.txt

%changelog
* Sun Aug 30 2026 ConMan maintainers - ${RPM_VERSION}-1
- Automated ConMan package
EOF

rpmbuild --define "_topdir ${TOP}" --define "_buildhost build.conman.invalid" \
    -bb "${TOP}/SPECS/conman.spec"
BUILT=$(find "${TOP}/RPMS" -type f -name '*.rpm' -print -quit)
[ -n "$BUILT" ] || die "rpmbuild produced no binary RPM"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
ARTIFACT="${OUTPUT_DIR}/conman-$(artifact_version "$VERSION")-linux-${ARCH}.rpm"
cp "$BUILT" "$ARTIFACT"
rpm -qpl "$ARTIFACT" >"${WORK}/contents.txt"
grep -q '/usr/bin/conmanctl$' "${WORK}/contents.txt" || die "RPM is missing conmanctl"
rpm -qp --requires "$ARTIFACT" >"${WORK}/requires.txt"
grep -Fxq 'glibc >= 2.35' "${WORK}/requires.txt" || die "RPM is missing the measured glibc floor"
grep -Fxq 'fontconfig >= 2.12.6' "${WORK}/requires.txt" || die "RPM is missing the measured fontconfig floor"
grep -Fxq 'libgcc' "${WORK}/requires.txt" || die "RPM is missing its libgcc runtime requirement"
write_sha256 "$ARTIFACT"
printf 'RPM: %s\n' "$ARTIFACT"
