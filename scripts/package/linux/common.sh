#!/usr/bin/env bash
set -euo pipefail

linux_package_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

need_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

normalize_arch() {
    case "$1" in
        x86_64|amd64) printf 'x86_64\n' ;;
        aarch64|arm64) printf 'aarch64\n' ;;
        *) die "unsupported Linux architecture: $1" ;;
    esac
}

deb_arch() {
    case "$1" in
        x86_64) printf 'amd64\n' ;;
        aarch64) printf 'arm64\n' ;;
        *) die "unsupported Debian architecture: $1" ;;
    esac
}

rpm_arch() {
    case "$1" in
        x86_64) printf 'x86_64\n' ;;
        aarch64) printf 'aarch64\n' ;;
        *) die "unsupported RPM architecture: $1" ;;
    esac
}

require_release_binaries() {
    local binary_dir=$1
    [ -x "${binary_dir}/conman" ] || die "missing executable: ${binary_dir}/conman"
    [ -x "${binary_dir}/conmanctl" ] || die "missing executable: ${binary_dir}/conmanctl"
    case "$(uname -s)" in Linux) ;; *) die "Linux packaging requires a Linux host" ;; esac
    file "${binary_dir}/conman" | grep -q 'ELF ' || die "conman is not a Linux ELF executable"
    file "${binary_dir}/conmanctl" | grep -q 'ELF ' || die "conmanctl is not a Linux ELF executable"
}

require_finalized_stage() {
    local binary_dir=$1 metadata="${1}/release-metadata.json"
    [ -f "$metadata" ] || die "missing release finalization metadata: $metadata (use build-portable-container.sh)"
    python3 - "$metadata" <<'PY' || die "release stage is not finalized for Linux"
import json
import sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data.get("platform") == "linux-x86_64"
assert data.get("packed_with_upx") is True
assert sorted(data.get("executables", [])) == ["conman", "conmanctl"]
PY
}

binary_version() {
    local binary_dir=$1 conman_version ctl_version
    conman_version=$("${binary_dir}/conman" --version | awk 'NF { value=$NF } END { print value }')
    ctl_version=$("${binary_dir}/conmanctl" --version | awk 'NF { value=$NF } END { print value }')
    [ -n "$conman_version" ] || die "conman --version returned no version"
    [ "$conman_version" = "$ctl_version" ] || \
        die "binary version mismatch: conman=${conman_version}, conmanctl=${ctl_version}"
    printf '%s\n' "$conman_version"
}

require_expected_version() {
    local actual=$1 expected=${EXPECTED_VERSION:-}
    if [ -n "$expected" ] && [ "$actual" != "$expected" ]; then
        die "binary version mismatch: expected ${expected}, got ${actual}"
    fi
}

artifact_version() {
    printf '%s' "$1" | sed 's/[^0-9A-Za-z._-]/-/g'
}

deb_version() {
    # Debian sorts ~ before the final release, matching SemVer prereleases.
    printf '%s' "$1" | sed 's/-/~/; s/[^0-9A-Za-z.+:~_-]/./g'
}

rpm_version() {
    # RPM tilde sorts before the empty suffix, matching SemVer prereleases.
    printf '%s' "$1" | sed 's/-/~/; s/+/./g; s/[^0-9A-Za-z._~]/./g'
}

install_distribution_notices() {
    local repo_root=$1 destination=$2 required
    for required in LICENSE-MIT LICENSE-APACHE; do
        [ -f "${repo_root}/${required}" ] || \
            die "missing authoritative project license: ${repo_root}/${required}"
    done
    install -Dm0644 "${repo_root}/LICENSE-MIT" "${destination}/LICENSE-MIT"
    install -Dm0644 "${repo_root}/LICENSE-APACHE" "${destination}/LICENSE-APACHE"
    install -Dm0644 "${repo_root}/crates/cm-ui/assets/fonts/NOTICE.md" \
        "${destination}/FONT-NOTICE.md"
    install -Dm0644 "${repo_root}/crates/cm-ui/assets/fonts/JetBrainsMono-OFL.txt" \
        "${destination}/JetBrainsMono-OFL.txt"
    install -Dm0644 "${repo_root}/crates/cm-ui/assets/fonts/SymbolsNerdFont-LICENSE-MIT.txt" \
        "${destination}/SymbolsNerdFont-LICENSE-MIT.txt"
}

install_desktop_payload() {
    local root=$1 repo_root=$2
    install -Dm0755 "${root}/../source/conman" "${root}/usr/bin/conman"
    install -Dm0755 "${root}/../source/conmanctl" "${root}/usr/bin/conmanctl"
    install -Dm0644 "${repo_root}/packaging/linux/com.marcos0ft.conman.desktop" \
        "${root}/usr/share/applications/com.marcos0ft.conman.desktop"
    install -Dm0644 "${repo_root}/packaging/linux/com.marcos0ft.conman.metainfo.xml" \
        "${root}/usr/share/metainfo/com.marcos0ft.conman.appdata.xml"
    install -Dm0644 "${repo_root}/resources/ConMan_128.png" \
        "${root}/usr/share/icons/hicolor/128x128/apps/com.marcos0ft.conman.png"
    install_distribution_notices "$repo_root" "${root}/usr/share/doc/conman"
}

write_sha256() {
    local artifact=$1
    (cd "$(dirname "$artifact")" && sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256")
}

verify_sha256() {
    local path=$1 expected=$2 actual
    [ -f "$path" ] || die "file not found for checksum verification: $path"
    actual=$(sha256sum "$path" | awk '{print $1}')
    [ "$actual" = "$expected" ] || \
        die "checksum mismatch for $path: expected $expected, got $actual"
}

ldd_reports_static() {
    local output=$1
    printf '%s\n' "$output" | grep -qiE \
        'not a dynamic executable|not a valid dynamic program|statically linked' \
        || printf '%s\n' "$output" | grep -qEx \
        '[[:space:]]*/lib/ld-musl-[^[:space:]]+ \(0x[0-9a-fA-F]+\)'
}

assert_fully_static_elf() {
    local binary=$1 ldd_output
    need_command readelf
    file "$binary" | grep -q 'ELF ' || die "$binary is not an ELF executable"
    if readelf -lW "$binary" | grep -q 'INTERP'; then
        die "$binary has an ELF interpreter and is not fully static"
    fi
    if readelf -dW "$binary" 2>/dev/null | grep -q '(NEEDED)'; then
        die "$binary has DT_NEEDED dependencies and is not fully static"
    fi
    # glibc ldd returns success for static PIE and prints "statically linked".
    # Depending on the musl release, ldd either rejects static PIE or prints one
    # loader self-mapping even though the ELF has neither PT_INTERP nor NEEDED.
    # Accept only those bounded diagnoses; never accept a resolved dependency.
    ldd_output=$(ldd "$binary" 2>&1 || true)
    if printf '%s\n' "$ldd_output" | grep -q '=>'; then
        die "$binary has dependencies according to ldd"
    fi
    if ! ldd_reports_static "$ldd_output"; then
        printf '%s\n' "$ldd_output" >&2
        die "could not prove that $binary is fully static"
    fi
}
