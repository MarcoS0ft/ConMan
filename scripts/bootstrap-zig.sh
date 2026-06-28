#!/usr/bin/env bash
# Bootstrap the EXACT Zig toolchain that libghostty-vt-sys needs (0.15.2).
#
# The pinned Ghostty commit rejects Zig 0.16.0 (winget/Homebrew ship 0.16.0 — it
# is WRONG here). This downloads 0.15.2 to a project-local `.zig/` directory and
# prints the line to put it on PATH. No network access happens in build.rs.
#
# Usage:
#   scripts/bootstrap-zig.sh              # ensure 0.15.2 is available; print PATH hint
#   eval "$(scripts/bootstrap-zig.sh --export)"   # also export PATH in this shell
#
# Idempotent: if a Zig 0.15.2 is already on PATH or already downloaded, it is reused.
set -euo pipefail

ZIG_VERSION="0.15.2"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_ROOT="${REPO_ROOT}/.zig"

EXPORT_MODE=0
[ "${1:-}" = "--export" ] && EXPORT_MODE=1

log() { [ "$EXPORT_MODE" -eq 1 ] && echo "$@" >&2 || echo "$@"; }

emit_path() {
    # $1 = directory containing the zig binary
    if [ "$EXPORT_MODE" -eq 1 ]; then
        printf 'export PATH="%s:$PATH"\n' "$1"
    else
        log ""
        log "Zig ${ZIG_VERSION} ready at: $1"
        log "Add it to PATH for this shell:"
        log "    export PATH=\"$1:\$PATH\""
    fi
}

# 1. Already correct on PATH?
if command -v zig >/dev/null 2>&1; then
    have="$(zig version 2>/dev/null || true)"
    if [ "$have" = "$ZIG_VERSION" ]; then
        log "Zig ${ZIG_VERSION} already on PATH ($(command -v zig)). Nothing to do."
        [ "$EXPORT_MODE" -eq 1 ] && printf '\n'
        exit 0
    fi
    log "Note: 'zig' on PATH is ${have:-unknown} (need ${ZIG_VERSION}); installing a project-local copy."
fi

# 2. Determine the ziglang.org target triple (arch-os).
arch="$(uname -m)"
case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) log "Unsupported CPU arch: $arch"; exit 1 ;;
esac
case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="macos" ;;
    *) log "Unsupported OS: $(uname -s). On Windows use scripts/bootstrap-zig.ps1."; exit 1 ;;
esac
triple="${arch}-${os}"
name="zig-${triple}-${ZIG_VERSION}"
zig_dir="${DEST_ROOT}/${name}"

# 3. Already downloaded?
if [ -x "${zig_dir}/zig" ] && [ "$("${zig_dir}/zig" version 2>/dev/null || true)" = "$ZIG_VERSION" ]; then
    emit_path "$zig_dir"
    exit 0
fi

# 4. Download + (best-effort) verify + extract.
url="https://ziglang.org/download/${ZIG_VERSION}/${name}.tar.xz"
mkdir -p "$DEST_ROOT"
tarball="${DEST_ROOT}/${name}.tar.xz"
log "Downloading ${url} ..."
curl -fsSL --retry 3 -o "$tarball" "$url"

# Verify sha256 against the official index when tooling is available.
if command -v sha256sum >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    want="$(curl -fsSL https://ziglang.org/download/index.json 2>/dev/null \
        | python3 -c "import sys,json;print(json.load(sys.stdin)['${ZIG_VERSION}']['${triple}']['shasum'])" 2>/dev/null || true)"
    if [ -n "$want" ]; then
        got="$(sha256sum "$tarball" | cut -d' ' -f1)"
        if [ "$want" != "$got" ]; then
            log "ERROR: sha256 mismatch for ${name}.tar.xz"
            log "  expected $want"
            log "  got      $got"
            rm -f "$tarball"
            exit 1
        fi
        log "sha256 verified."
    else
        log "Warning: could not fetch expected sha256 from the index; skipping verification."
    fi
else
    log "Warning: sha256sum/python3 unavailable; skipping checksum verification."
fi

log "Extracting ..."
rm -rf "$zig_dir"
tar -xf "$tarball" -C "$DEST_ROOT"
rm -f "$tarball"

# 5. Confirm and report.
got_ver="$("${zig_dir}/zig" version 2>/dev/null || true)"
if [ "$got_ver" != "$ZIG_VERSION" ]; then
    log "ERROR: extracted Zig reports '${got_ver}', expected ${ZIG_VERSION}."
    exit 1
fi
emit_path "$zig_dir"
